(in-package #:gr8s/tests)

(in-suite gr8s)

(defun write-test-octets (path octets)
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :element-type '(unsigned-byte 8)
                          :if-exists :supersede
                          :if-does-not-exist :create)
    (write-sequence octets stream)))

(test runtime-assets-load-and-materialize-executable-octets
  (let* ((root
           (merge-pathnames
            (format nil "gr8s-runtime-assets-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (source (merge-pathnames "source/" root))
         (destination (merge-pathnames "destination/" root))
         (containerd #(127 69 76 70 1 2 3))
         (shim #(127 69 76 70 4 5))
         (runc #(127 69 76 70 6 7 8 9))
         (bridge #(127 69 76 70 10))
         (host-local #(127 69 76 70 11))
         (loopback #(127 69 76 70 12))
         (firewall #(127 69 76 70 13))
         (whistler-program #(127 69 76 70 14)))
    (unwind-protect
         (progn
           (write-test-octets (merge-pathnames "bin/containerd" source)
                              containerd)
           (write-test-octets
            (merge-pathnames "bin/containerd-shim-runc-v2" source) shim)
           (write-test-octets (merge-pathnames "bin/runc" source) runc)
           (write-test-octets (merge-pathnames "bin/bridge" source) bridge)
           (write-test-octets (merge-pathnames "bin/host-local" source)
                              host-local)
           (write-test-octets (merge-pathnames "bin/loopback" source) loopback)
           (write-test-octets (merge-pathnames "bin/firewall" source) firewall)
           (write-test-octets
            (merge-pathnames "bin/gr8s-whistler.bpf.o" source)
            whistler-program)
           (let ((assets (gr8s::load-runtime-assets source)))
             (is (equal '("containerd" "containerd-shim-runc-v2" "runc"
                          "bridge" "host-local" "loopback" "firewall"
                          "gr8s-whistler.bpf.o")
                        (mapcar #'gr8s::runtime-asset-name assets)))
             (gr8s::materialize-runtime-assets assets destination)
             (loop for asset in assets
                   for expected in (list containerd shim runc bridge host-local
                                         loopback firewall whistler-program)
                   for path = (merge-pathnames
                               (gr8s::runtime-asset-name asset) destination)
                   do (is (equalp expected (gr8s::read-file-octets path)))
                      (is (plusp
                           (logand #o111
                                   (sb-posix:stat-mode (sb-posix:stat path))))))))
      (uiop:delete-directory-tree root :validate t
                                  :if-does-not-exist :ignore))))

(test embedded-runtime-assets-are-explicitly-installed-for-the-dump
  (let* ((root
           (merge-pathnames
            (format nil "gr8s-embedded-assets-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (gr8s::*embedded-runtime-assets* nil))
    (unwind-protect
         (progn
           (dolist (name '("containerd" "containerd-shim-runc-v2" "runc"
                           "bridge" "host-local" "loopback" "firewall"
                           "gr8s-whistler.bpf.o"))
             (write-test-octets (merge-pathnames (format nil "bin/~A" name) root)
                                #(1 2 3)))
           (gr8s::embed-runtime-assets root)
           (is (= 8 (length gr8s::*embedded-runtime-assets*)))
           (is (gr8s::embedded-runtime-assets-p)))
      (uiop:delete-directory-tree root :validate t
                                  :if-does-not-exist :ignore))))

(test runtime-assets-live-on-a-mounted-filesystem-for-the-callback
  (let* ((root
           (merge-pathnames
            (format nil "gr8s-runtime-mount-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (events nil)
         (assets
           (list (gr8s::make-runtime-asset
                  :name "containerd" :octets #(1 2 3))
                 (gr8s::make-runtime-asset
                  :name "containerd-shim-runc-v2" :octets #(4 5))
                 (gr8s::make-runtime-asset
                  :name "runc" :octets #(6 7 8)))))
    (unwind-protect
         (gr8s::call-with-runtime-assets
          assets root
          (lambda (paths)
            (push :body events)
            (is (equalp #(1 2 3)
                        (gr8s::read-file-octets
                         (cdr (assoc "containerd" paths :test #'string=)))))
            (is (every #'probe-file (mapcar #'cdr paths))))
          :mounter (lambda (directory)
                     (is (equal (uiop:ensure-directory-pathname root)
                                (uiop:ensure-directory-pathname directory)))
                     (push :mount events))
          :unmounter (lambda (directory)
                       (declare (ignore directory))
                       (push :unmount events)))
         (is (equal '(:mount :body :unmount) (reverse events)))
      (uiop:delete-directory-tree root :validate t
                                  :if-does-not-exist :ignore))))

(test runtime-preparation-links-the-cni-name-to-the-current-image
  (let* ((root
           (merge-pathnames
            (format nil "gr8s-runtime-cni-link-~36R/" (random (expt 36 8)))
            (uiop:temporary-directory)))
         (image (merge-pathnames "gr8s.bin" root))
         (runtime (merge-pathnames "runtime/" root))
         (assets (list (gr8s::make-runtime-asset
                        :name "containerd" :octets #(1 2 3)))))
    (unwind-protect
         (progn
           (write-test-octets image #(127 69 76 70))
           (gr8s::call-with-runtime-assets
            assets runtime
            (lambda (paths)
              (declare (ignore paths))
              (let ((link (merge-pathnames "gr8s" runtime)))
                (is (probe-file link))
                (is (equal (truename image) (truename link)))))
            :mounter (lambda (directory) (declare (ignore directory)))
            :unmounter (lambda (directory) (declare (ignore directory)))
            :cni-executable image))
      (uiop:delete-directory-tree root :validate t
                                  :if-does-not-exist :ignore))))

(test surviving-filesystem-mount-detection-handles-escaped-paths-and-optional-fields
  (with-temporary-store (store path)
    (assert store)
    (let* ((directory (merge-pathnames "mount with spaces/" path)))
      (ensure-directories-exist (merge-pathnames "marker" directory))
      (let* ((encoded (format nil "~{~A~^\\040~}"
                              (uiop:split-string
                               (string-right-trim "/" (namestring (truename directory)))
                               :separator '(#\Space))))
             (mount-info (format nil "42 1 0:1 / ~A rw,nosuid shared:77 - bpf gr8s-bpf rw~%" encoded)))
        (is-true (gr8s::filesystem-mounted-at-p directory "bpf" :mount-info mount-info))
        (is-false (gr8s::filesystem-mounted-at-p directory "tmpfs" :mount-info mount-info))
        (is-false (gr8s::filesystem-mounted-at-p path "bpf" :mount-info mount-info))))))
