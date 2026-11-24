;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Put a release in place on this host (podster-igs.2): fetch the package for
;;;; this host's architecture, in the form gr8s was installed in -- an RPM or DEB
;;;; when a package manager owns the executable, else the bare executable, as
;;;; install.sh leaves it -- check it against the signed release, and install it.
;;;;
;;;; A running gr8s that installs its own successor must not be inside what the
;;;; install restarts: the package's scripts restart gr8s-server, and systemd stops
;;;; every process in the unit's cgroup, the package manager among them. So from
;;;; inside the service the install runs as a transient unit of its own.

(in-package #:gr8s.upgrade)

(defparameter *upgrade-directory* #p"/var/lib/gr8s/upgrade/"
  "Where fetched packages wait to be installed.")

(defun host-architecture ()
  "This executable's Kubernetes architecture name."
  (cond ((member :x86-64 *features*) "amd64")
        ((member :arm64 *features*) "arm64")
        (t (string-downcase (machine-type)))))

(defun gr8s-program ()
  "The path of this gr8s executable; signal when running from source, under SBCL."
  (let ((runtime sb-ext:*runtime-pathname*))
    (when (or (null runtime) (search "sbcl" (file-namestring runtime)))
      (upgrade-fail "gr8s is running from source, not an installed executable; there is nothing to upgrade"))
    (namestring (truename runtime))))

(defun run-program-status (program &rest arguments)
  "Run PROGRAM with ARGUMENTS; (values exit-code output)."
  (multiple-value-bind (output error-output status)
      (uiop:run-program (cons program arguments) :ignore-error-status t
                                                 :output :string :error-output :output)
    (declare (ignore error-output))
    (values status output)))

(defun program-available-p (name)
  (ignore-errors (zerop (run-program-status "sh" "-c" (format nil "command -v ~A >/dev/null" name)))))

(defun installed-gr8s-program ()
  "The gr8s this host's services run: the executable of a running gr8s-server or
gr8s-agent, else the gr8s on PATH, else this one. `gr8s upgrade self' may run from
anywhere, and must upgrade the gr8s that is installed, not itself."
  (or (loop for unit in '("gr8s-server.service" "gr8s-agent.service")
            for pid = (ignore-errors
                       (parse-integer (string-trim '(#\Newline #\Space)
                                                   (nth-value 1 (run-program-status "systemctl" "show" "-p" "MainPID" "--value" unit)))))
            for executable = (and pid (plusp pid)
                                  (ignore-errors (sb-posix:readlink (format nil "/proc/~D/exe" pid))))
            when executable
              return (let ((deleted (search " (deleted)" executable)))
                       (if deleted (subseq executable 0 deleted) executable)))
      (let ((path (string-trim '(#\Newline #\Space)
                               (nth-value 1 (run-program-status "sh" "-c" "command -v gr8s")))))
        (and (plusp (length path)) (probe-file path) (namestring (truename path))))
      (gr8s-program)))

(defun installed-program-version (program)
  "What PROGRAM says its release is, or NIL."
  (multiple-value-bind (status output) (run-program-status program "version")
    (and (zerop status)
         (let ((words (uiop:split-string (string-trim '(#\Newline) (first (uiop:split-string output :separator '(#\Newline)))))))
           (second words)))))

(defun host-package-format (&optional (program (gr8s-program)))
  "How gr8s was installed: \"rpm\" or \"deb\" when that package manager owns PROGRAM,
else \"binary\"."
  (cond ((and (program-available-p "rpm") (zerop (run-program-status "rpm" "-qf" program))) "rpm")
        ((and (program-available-p "dpkg") (zerop (run-program-status "dpkg" "-S" program))) "deb")
        (t "binary")))

(defun own-systemd-unit ()
  "The systemd service this process runs in, from its cgroup, or NIL."
  (let ((line (ignore-errors (with-open-file (in "/proc/self/cgroup") (read-line in nil)))))
    (when line
      (let ((unit (car (last (uiop:split-string line :separator '(#\/))))))
        (and (uiop:string-suffix-p unit ".service") unit)))))

(defun prepare-host-upgrade (reference &key (directory *upgrade-directory*) (keys *trusted-release-keys*)
                                            format architecture username password)
  "Fetch the release REFERENCE names and, checked against its signature, the package
this host installs: a plist of :version :format :architecture :path :digest."
  (let* ((artifact (fetch-release-artifact reference :keys keys :username username :password password))
         (format (or format (host-package-format)))
         (architecture (or architecture (host-architecture)))
         (package (or (find-if (lambda (package)
                                 (and (equal format (getf package :format))
                                      (equal architecture (getf package :architecture))))
                               (release-artifact-packages artifact))
                      (upgrade-fail "release ~A has no ~A package for ~A"
                                    (release-artifact-version artifact) format architecture))))
    (list :version (release-artifact-version artifact) :format format :architecture architecture
          :digest (release-artifact-digest artifact)
          :path (namestring (fetch-release-package
                             artifact package
                             (merge-pathnames (format nil "~A/" (release-artifact-version artifact))
                                              (uiop:ensure-directory-pathname directory)))))))

(defun shell-quote (text)
  (format nil "'~A'" (cl-ppcre:regex-replace-all "'" text "'\\\\''")))

(defun install-command (prepared program unit)
  "The shell command that installs PREPARED and has the service run it."
  (let ((path (shell-quote (getf prepared :path))))
    (cond ((equal "rpm" (getf prepared :format))
           ;; Its scripts restart gr8s-server and gr8s-agent, whichever is running.
           (format nil "rpm -U --oldpackage --replacepkgs ~A" path))
          ((equal "deb" (getf prepared :format))
           (format nil "dpkg -i ~A" path))
          (t
           (let ((new (shell-quote (concatenate 'string program ".gr8s-new"))))
             (format nil "install -m 0755 ~A ~A && mv -f ~A ~A~@[ && systemctl restart ~A~]"
                     path new new (shell-quote program) (and unit (shell-quote unit))))))))

(defun install-host-upgrade (prepared &key (program (gr8s-program)) (unit (own-systemd-unit)))
  "Install PREPARED, as PREPARE-HOST-UPGRADE returns it. From inside a systemd service
the install runs as a transient unit, and this returns at once with its name; the
service restarts on the new release as it ends. Otherwise it runs here, and returns
its output."
  (let ((command (install-command prepared program unit)))
    (if unit
        (let ((name (format nil "gr8s-upgrade-~D" (get-universal-time))))
          (multiple-value-bind (status output)
              (run-program-status "systemd-run" "--unit" name "--collect" "--quiet"
                                  "--description" (format nil "gr8s upgrade to ~A" (getf prepared :version))
                                  "/bin/sh" "-c" command)
            (unless (zerop status)
              (upgrade-fail "systemd-run could not start the upgrade: ~A" (string-trim '(#\Newline) output)))
            (values name :started)))
        (multiple-value-bind (status output) (run-program-status "/bin/sh" "-c" command)
          (unless (zerop status)
            (upgrade-fail "installing ~A failed: ~A" (getf prepared :path) (string-trim '(#\Newline) output)))
          (values output :installed)))))

(defun run-host-upgrade (reference say)
  "Install the signed release REFERENCE names on this host, calling SAY with each step:
fetch and check it, then install it, unless this host runs that release already. The
install restarts gr8s, ending the caller with it (podster-igs.3)."
  (funcall say (format nil "fetching ~A" reference))
  (let ((prepared (prepare-host-upgrade reference)))
    (funcall say (format nil "release ~A verified; ~A package ~A for ~A"
                         (getf prepared :version) (getf prepared :format)
                         (file-namestring (getf prepared :path)) (getf prepared :architecture)))
    (if (equal (getf prepared :version) (gr8s.foundation::kubernetes-git-version))
        (funcall say (format nil "this host runs ~A already" (getf prepared :version)))
        (multiple-value-bind (what how) (install-host-upgrade prepared)
          (funcall say (if (eq how :started)
                           (format nil "installing as systemd unit ~A; gr8s restarts on ~A" what (getf prepared :version))
                           (format nil "installed ~A; restart gr8s to run it" (getf prepared :version))))))
    prepared))
