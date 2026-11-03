(load (merge-pathnames "network-test-support.lisp" *load-truename*))
(in-package #:gr8s)

(let ((namespaces nil)
      (contexts nil))
  (unwind-protect
       (progn
         (with-open-file (stream "/proc/sys/net/ipv4/ip_forward"
                                 :direction :output :if-exists :overwrite)
           (write-line "1" stream))
         (dotimes (index 2)
           (let* ((fd (test-network-namespace))
                  (context (make-cni-context
                            :container-id (format nil "test-sandbox-~D" index)
                            :interface-name "eth0"
                            :netns (format nil "/proc/self/fd/~D" fd)))
                  (address (format nil "10.42.0.~D" (1+ index))))
             (push fd namespaces)
             (push context contexts)
             (configure-routed-veth context address)
             (check-routed-cni-link context address)
             ;; Model a crash before either ownership alias was installed.
             (set-network-link-owner (routed-cni-host-name context) "")
             (call-with-cni-network-namespace
              (cni-context-netns context)
              (lambda () (set-network-link-owner "eth0" "")))
             ;; Repeated ADD adopts matching MAC identities and repairs settings
             ;; without replacing a live veth.
             (let ((before (native-interface-index (routed-cni-host-name context))))
               (configure-routed-veth context address)
               (assert (= before
                          (native-interface-index (routed-cni-host-name context)))))
             (check-routed-cni-link context address)
             ;; A foreign ownership tag must win even on a matching link.
             (set-network-link-owner (routed-cni-host-name context) "another-owner")
             (assert (handler-case (progn (configure-routed-veth context address) nil)
                       (cni-error () t)))
             (set-network-link-owner (routed-cni-host-name context) (routed-cni-owner context))
             (uiop:run-program (list "ping" "-n" "-c" "1" "-W" "2" address)
                               :output *standard-output* :error-output *error-output*)))
         (call-with-cni-network-namespace
          (cni-context-netns (first contexts))
          (lambda ()
            (uiop:run-program '("ping" "-n" "-c" "2" "-W" "2" "10.42.0.1")
                              :output *standard-output* :error-output *error-output*)))
         ;; Namespace transitions must restore the calling worker thread,
         ;; even when its starting namespace differs from the process leader.
         (let ((failure nil)
               (path (cni-context-netns (first contexts))))
           (bt:join-thread
            (bt:make-thread
             (lambda ()
               (handler-case
                   (call-with-cni-network-namespace
                    path
                    (lambda ()
                      ;; The nested call must restore this Pod namespace.
                      (call-with-cni-network-namespace
                       (cni-context-netns (second contexts))
                       (lambda () (assert (plusp (native-interface-index "eth0")))))
                      (assert (zerop (native-interface-index
                                      (routed-cni-host-name (first contexts)))))
                      (assert (plusp (native-interface-index "eth0")))))
                 (error (condition) (setf failure condition))))))
           (when failure (error failure)))
         ;; Destroy the namespace handle before DEL to cover a vanished netns.
         (dolist (fd namespaces) (sb-posix:close fd))
         (setf namespaces nil)
         (dolist (context contexts)
           (setf (cni-context-netns context) "")
           (remove-routed-cni-link context)
           (remove-routed-cni-link context)
           (assert (zerop (native-interface-index (routed-cni-host-name context)))))
         (format t "gr8s native routed-veth connectivity test passed~%"))
    (dolist (context contexts) (ignore-errors (remove-routed-cni-link context)))
    (dolist (fd namespaces) (ignore-errors (sb-posix:close fd)))))
