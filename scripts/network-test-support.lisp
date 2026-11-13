(require :asdf)
(asdf:load-system :gr8s)

(in-package #:gr8s.network)

;; Invoked by make test-routed-network inside a disposable user/network
;; namespace. No host links, routes, or forwarding settings are changed.
(sb-alien:define-alien-routine ("unshare" %test-unshare) sb-alien:int
  (flags sb-alien:int))

(defun test-network-namespace ()
  (let ((original (sb-posix:open "/proc/thread-self/ns/net" sb-posix:o-rdonly 0)))
    (unwind-protect
         (progn
           (unless (zerop (%test-unshare #x40000000))
             (error "cannot create test network namespace: ~A"
                    (sb-int:strerror (sb-alien:get-errno))))
           (unwind-protect
                (sb-posix:open "/proc/thread-self/ns/net" sb-posix:o-rdonly 0)
             (unless (zerop (%linux-setns original 0))
               (error "cannot restore test router namespace"))))
      (sb-posix:close original))))

