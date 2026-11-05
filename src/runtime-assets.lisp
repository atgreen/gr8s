(in-package #:gr8s)

(defparameter +runtime-asset-names+
  '("containerd" "containerd-shim-runc-v2" "runc"
    "bridge" "host-local" "loopback" "firewall"))

(defstruct runtime-asset
  name
  octets)

(defvar *embedded-runtime-assets* nil)

#+linux
(sb-alien:define-alien-routine ("mount" %linux-mount) sb-alien:int
  (source sb-alien:c-string)
  (target sb-alien:c-string)
  (filesystem-type sb-alien:c-string)
  (mount-flags sb-alien:unsigned-long)
  (data sb-alien:c-string))

#+linux
(sb-alien:define-alien-routine ("umount2" %linux-umount) sb-alien:int
  (target sb-alien:c-string)
  (flags sb-alien:int))

(defun read-file-octets (path)
  (with-open-file (stream path :direction :input
                                :element-type '(unsigned-byte 8))
    (let ((octets (make-array (file-length stream)
                              :element-type '(unsigned-byte 8))))
      (read-sequence octets stream)
      octets)))

(defun load-runtime-assets (directory)
  (let ((root (uiop:ensure-directory-pathname directory)))
    (loop for name in +runtime-asset-names+
          for path = (merge-pathnames (format nil "bin/~A" name) root)
          unless (probe-file path)
            do (error "missing runtime asset: ~A" path)
          collect (make-runtime-asset
                   :name name
                   :octets (read-file-octets path)))))

(defun write-runtime-asset (asset directory)
  (let ((path (merge-pathnames
               (runtime-asset-name asset)
               (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist path)
    (with-open-file (stream path
                            :direction :output
                            :element-type '(unsigned-byte 8)
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (write-sequence (runtime-asset-octets asset) stream))
    (sb-posix:chmod path #o755)
    path))

(defun materialize-runtime-assets (assets directory)
  (mapcar (lambda (asset)
            (write-runtime-asset asset directory))
          assets))

(defun filesystem-mounted-at-p (directory filesystem
                                &key (mount-info (uiop:read-file-string #P"/proc/thread-self/mountinfo")))
  (let* ((target (string-right-trim "/" (namestring (truename directory))))
         (encoded
           (with-output-to-string (stream)
             (loop for character across target
                   do (case character
                        (#\Space (write-string "\\040" stream))
                        (#\Tab (write-string "\\011" stream))
                        (#\Newline (write-string "\\012" stream))
                        (#\\ (write-string "\\134" stream))
                        (otherwise (write-char character stream)))))))
    (loop for line in (uiop:split-string mount-info :separator '(#\Newline))
          for fields = (uiop:split-string line :separator '(#\Space))
          for separator = (position "-" fields :test #'string=)
          thereis (and separator (>= (length fields) (+ separator 3))
                       (string= encoded (nth 4 fields))
                       (string= filesystem (nth (1+ separator) fields))))))

(defun mount-runtime-tmpfs (directory)
  #+linux
  (let ((target (namestring (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist (merge-pathnames ".mount-point" target))
    ;; MS_NOSUID | MS_NODEV. Executable mappings are intentionally allowed.
    (unless (zerop (%linux-mount "gr8s-runtime" target "tmpfs" #x6
                                "mode=0755,size=128m"))
      (error "could not mount the gr8s runtime tmpfs at ~A: ~A"
             target (sb-int:strerror (sb-alien:get-errno)))))
  #-linux
  (error "embedded runtime assets require Linux"))

(defun unmount-runtime-tmpfs (directory)
  #+linux
  (let ((target (namestring (uiop:ensure-directory-pathname directory))))
    (unless (zerop (%linux-umount target 0))
      (error "could not unmount the gr8s runtime tmpfs at ~A: ~A"
             target (sb-int:strerror (sb-alien:get-errno)))))
  #-linux
  (declare (ignore directory)))

(defun runtime-asset-paths (assets directory)
  (mapcar (lambda (asset)
            (cons (runtime-asset-name asset)
                  (merge-pathnames
                   (runtime-asset-name asset)
                   (uiop:ensure-directory-pathname directory))))
          assets))

(defun current-native-executable ()
  #+linux (truename #P"/proc/self/exe")
  #-linux (error "the gr8s CNI executable requires Linux"))

(defparameter +cni-image-command+ "internal-write-cni-image"
  "Hidden command: write the CNI plugin image to the path that follows it.")

(defun write-cni-plugin-image (path)
  "Dump this image to PATH uncompressed and without its runtime assets, then exit.
It must run in a process of its own, because dumping ends the process."
  (setf *embedded-runtime-assets* nil)
  (sb-ext:save-lisp-and-die path :executable t :toplevel (lambda () (uiop:quit (main)))))

(defun prepare-cni-plugin-image (directory executable)
  "Return the path of a CNI plugin image written under DIRECTORY, or NIL if it can't be
written or run, when the caller keeps using EXECUTABLE. Containerd execs the plugin for
every sandbox add and delete, and a compressed image inflates all of its embedded
runtime assets each time, which takes about 0.67s and 185MB on a test VM."
  (handler-case
      (let* ((directory (uiop:ensure-directory-pathname directory))
             (path (namestring (merge-pathnames "gr8s" directory)))
             (pending (concatenate 'string path ".pending")))
        (ensure-directories-exist directory)
        (when (and (zerop (sb-ext:process-exit-code
                           (sb-ext:run-program (namestring executable)
                                               (list +cni-image-command+ pending)
                                               :input nil :output nil :error nil)))
                   ;; Also proves this location allows exec.
                   (zerop (sb-ext:process-exit-code
                           (sb-ext:run-program pending nil
                                               :environment (cons "CNI_COMMAND=VERSION"
                                                                  (sb-ext:posix-environ))
                                               :input nil :output nil :error nil))))
          (rename-file pending path)
          path))
    (error (condition)
      (format *error-output* "gr8s: using the compressed image as the CNI plugin: ~A~%" condition)
      nil)))

(defun install-cni-executable-link (directory executable)
  (let ((link (merge-pathnames
               "gr8s"
               (uiop:ensure-directory-pathname directory)))
        (target (truename executable)))
    (ignore-errors (delete-file link))
    (sb-posix:symlink (namestring target) (namestring link))
    link))

(defun call-with-runtime-assets
    (assets directory function
     &key (mounter #'mount-runtime-tmpfs)
          (unmounter #'unmount-runtime-tmpfs)
          (cni-executable (current-native-executable))
          (cni-image-preparer (when (embedded-runtime-assets-p) #'prepare-cni-plugin-image)))
  (let* ((root (uiop:ensure-directory-pathname directory))
         ;; The runtime tmpfs is sized for the assets, so this goes beside it.
         (image-directory (merge-pathnames "cni-plugin/" (uiop:pathname-parent-directory-pathname root))))
    (ensure-directories-exist (merge-pathnames ".mount-point" root))
    (funcall mounter root)
    (unwind-protect
         (progn
           (materialize-runtime-assets assets root)
           (install-cni-executable-link
            root (or (when cni-image-preparer
                       (funcall cni-image-preparer image-directory cni-executable))
                     cni-executable))
           (funcall function (runtime-asset-paths assets root)))
      (funcall unmounter root)
      (when cni-image-preparer
        (uiop:delete-directory-tree image-directory :validate t :if-does-not-exist :ignore)))))

(defun embed-runtime-assets (directory)
  (setf *embedded-runtime-assets* (load-runtime-assets directory)))

(defun embedded-runtime-assets-p ()
  (not (null *embedded-runtime-assets*)))
