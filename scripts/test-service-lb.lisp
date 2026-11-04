;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Privileged verification for the ClusterIP socket load-balancer dataplane
;;;; (podster-7q2.2).  Requires real root (CAP_BPF plus a writable cgroup2 and a
;;;; bpffs); unprivileged user namespaces cannot load a cgroup/connect4 program.
;;;;
;;;; It JIT-compiles the program in-process, creates and pins the maps, loads
;;;; the program, attaches it to a throwaway child cgroup, writes one
;;;; ClusterIP:port with two backends, and reads the entries back from the
;;;; kernel maps to confirm the byte-order contract survives a real round trip.
;;;; End-to-end connect() redirection through the attached program is covered by
;;;; the privileged smoke (podster-7q2.4), not here.
;;;;
;;;; Run:  make test-service-lb        (invokes this under sudo)

(require :asdf)

;; Resolve gr8s and its dependencies from this checkout, so the script loads the
;; same way whether run as the developer or, under sudo, as root.
(let ((project (truename (merge-pathnames "../" (uiop:pathname-directory-pathname *load-truename*)))))
  (asdf:initialize-source-registry
   `(:source-registry
     (:directory ,project)
     (:tree ,(merge-pathnames "ocicl/" project))
     :inherit-configuration)))

(asdf:load-system :gr8s)

(in-package #:gr8s)

(defvar *failures* 0)

(defun check (ok format &rest arguments)
  (format t "~&[~A] ~A~%" (if ok " ok " "FAIL") (apply #'format nil format arguments))
  (unless ok (incf *failures*)))

(defun run-service-lb-privileged-test ()
  (let* ((bpffs "/sys/fs/bpf")
         (pin-directory (format nil "~A/gr8s-service-lb-test-~D/" bpffs (sb-posix:getpid)))
         (cgroup-root "/sys/fs/cgroup")
         (cgroup-path (format nil "~A/gr8s-service-lb-test-~D" cgroup-root (sb-posix:getpid)))
         (dataplane nil))
    (unless (probe-file bpffs)
      (error "~A is not present; mount a bpffs there first" bpffs))
    ;; A child cgroup under the unified v2 hierarchy is just a directory.
    (ensure-directories-exist (concatenate 'string cgroup-path "/"))
    (unwind-protect
         (progn
           (setf dataplane (start-service-lb-dataplane cgroup-path pin-directory))
           (check (not (null (service-lb-dataplane-attachment dataplane)))
                  "program attached to cgroup ~A" cgroup-path)
           (check (probe-file (concatenate 'string pin-directory "gr8s_service_v4"))
                  "gr8s_service_v4 map pinned on bpffs")
           (check (probe-file (concatenate 'string pin-directory "gr8s_backend_v4"))
                  "gr8s_backend_v4 map pinned on bpffs")

           ;; Write 10.96.0.10:80 -> {10.88.1.5:8080, 10.88.2.7:8080} at slots 0,1.
           (service-lb-write-service dataplane "10.96.0.10" 80 0
                                     '(("10.88.1.5" . 8080) ("10.88.2.7" . 8080)))

           ;; Read the entries back from the real kernel maps.
           (let ((service (whistler/loader:map-lookup
                           (service-lb-service-table dataplane)
                           (service-lb-vip-key "10.96.0.10" 80)))
                 (backend0 (whistler/loader:map-lookup
                            (service-lb-backend-table dataplane)
                            (service-lb-backend-key 0)))
                 (backend1 (whistler/loader:map-lookup
                            (service-lb-backend-table dataplane)
                            (service-lb-backend-key 1))))
             (check (equalp (service-lb-service-value 2 0) service)
                    "service entry round-trips through the kernel map")
             (check (equalp (service-lb-backend-value "10.88.1.5" 8080) backend0)
                    "backend slot 0 round-trips through the kernel map")
             (check (equalp (service-lb-backend-value "10.88.2.7" 8080) backend1)
                    "backend slot 1 round-trips through the kernel map")))
      (when dataplane
        (ignore-errors (stop-service-lb-dataplane dataplane)))
      (ignore-errors (sb-posix:rmdir cgroup-path))
      (ignore-errors (uiop:delete-empty-directory pin-directory)))
    (if (zerop *failures*)
        (format t "~&service-lb privileged test: PASS~%")
        (format t "~&service-lb privileged test: ~D FAILURE(S)~%" *failures*))
    (sb-ext:exit :code (if (zerop *failures*) 0 1))))

(run-service-lb-privileged-test)
