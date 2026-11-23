;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;; Test-only forms loaded through an owned debug server in a disposable root VM.
(in-package #:gr8s.network)

(defvar *upgrade-probe-dataplane* nil)
(defvar *upgrade-probe-configuration* nil)
(defvar *upgrade-probe-context* nil)
(defvar *upgrade-probe-root* nil)
(defvar *upgrade-probe-before* nil)

(defun upgrade-probe-paths ()
  (multiple-value-list (cni-pin-paths *upgrade-probe-root* "endpoint" "ingress")))

(defun upgrade-probe-snapshot ()
  (let ((result nil))
    (dolist (directory (list (third (upgrade-probe-paths))
                             (service-lb-dataplane-pin-directory *upgrade-probe-dataplane*)))
      (dolist (path (directory (concatenate 'string (namestring directory) "*")))
        (let ((fd (whistler/loader:open-pinned-object (namestring path))))
          (unwind-protect
               (push (list (namestring path) (netlink-read-integer (bpf-object-kernel-info fd) 4 4)) result)
            (sb-posix:close fd)))))
    (sort result #'string< :key #'first)))

(defun upgrade-probe-setup (root netns interface)
  (setf *upgrade-probe-root* root
        *upgrade-probe-dataplane*
        (start-service-lb-dataplane "/sys/fs/cgroup" (concatenate 'string root "service-lb/")
                                   :packet-services t)
        *upgrade-probe-configuration*
        (make-cni-configuration :direction "ingress" :policy-interface-name interface
                                :endpoint-address "10.99.0.2" :map-pin-root root
                                :service-packet-root (concatenate 'string root "service-lb/"))
        *upgrade-probe-context* (make-cni-context :container-id "endpoint" :netns netns :interface-name "eth0"))
  (destructuring-bind (map-path link-path directory) (upgrade-probe-paths)
    (declare (ignore directory))
    (install-cni-policy *upgrade-probe-configuration* *upgrade-probe-context* map-path link-path))
  (setf *upgrade-probe-before* (upgrade-probe-snapshot))
  (list :passed t :snapshot *upgrade-probe-before*))

(defun upgrade-probe-current (&optional (completed 0))
  (let ((path (merge-pathnames "gr8s_pkt_stages" (third (upgrade-probe-paths)))))
    (unless (service-packet-gc-compatible-p *upgrade-probe-dataplane* :paths (constantly (list path)))
      (error "pipeline verification failed: ~S"
             (loop for message being the hash-values of (service-lb-dataplane-upgrade-warnings *upgrade-probe-dataplane*)
                   collect message)))
    (assert (equal *upgrade-probe-before* (upgrade-probe-snapshot)))
    (assert (= completed (service-lb-dataplane-upgrade-completed *upgrade-probe-dataplane*)))
    (list :passed t :current-programs-reused t)))

(defun upgrade-probe-allowed ()
  (gethash "allowedPackets" (read-cni-policy-counters *upgrade-probe-root* "endpoint")))

(defun upgrade-probe-partial ()
  (let* ((directory (third (upgrade-probe-paths)))
         (drop (load-packet-upgrade-blocker)))
    (unwind-protect
         (progn
           (dolist (direction '("ingress" "egress"))
             (let ((entry (whistler/loader:open-pinned-object
                           (concatenate 'string directory "tcx-" direction))))
               (unwind-protect
                    (let ((block (attach-packet-upgrade-blocker drop entry)))
                      (unwind-protect
                           (whistler/loader:pin-bpf-object
                            block (concatenate 'string directory "gr8s_pkt_upgrade_" direction))
                        (sb-posix:close block)))
                 (sb-posix:close entry))))
           (let ((fd (whistler/loader:open-pinned-object (concatenate 'string directory "gr8s_pkt_stages"))))
             (unwind-protect
                  (whistler/loader:map-delete (cni-policy-map-info fd "gr8s_pkt_stages") (service-lb-bytes 2 4))
               (sb-posix:close fd))))
      (sb-posix:close drop)))
  (destructuring-bind (map-path link-path directory) (upgrade-probe-paths)
    (declare (ignore directory))
    (assert (handler-case
                (progn (check-cni-policy *upgrade-probe-configuration* *upgrade-probe-context* map-path link-path) nil)
              (cni-error () t))))
  (list :passed t :blocked-and-incomplete t))

(defun upgrade-probe-verifier-failure ()
  (let* ((*service-egress-guard-specs* (copy-tree *service-egress-guard-specs*))
         (path (merge-pathnames "gr8s_pkt_stages" (third (upgrade-probe-paths))))
         (fds-before (length (directory "/proc/self/fd/*"))))
    ;; One replacement loads before a later one fails; no descriptor prefix
    ;; may leak and neither pinned drop guard may be removed on failure.
    (let* ((program (second (cdr *service-egress-guard-specs*)))
           (bytes (copy-seq (getf program :insns))))
      (setf (aref bytes 0) 255
            (getf program :insns) bytes))
    (assert (not (service-packet-gc-compatible-p *upgrade-probe-dataplane* :paths (constantly (list path)))))
    (assert (not (service-lb-dataplane-gc-compatible-p *upgrade-probe-dataplane*)))
    (assert (= fds-before (length (directory "/proc/self/fd/*"))))
    (dolist (pin (cni-upgrade-block-paths (first (upgrade-probe-paths)))) (assert (probe-file pin)))
    (list :passed t :gc-deferred t :descriptors-preserved t)))

(defun upgrade-probe-recover ()
  (let ((path (merge-pathnames "gr8s_pkt_stages" (third (upgrade-probe-paths)))))
    (unless (service-packet-gc-compatible-p *upgrade-probe-dataplane* :paths (constantly (list path)))
      (error "pipeline verification failed: ~S"
             (loop for message being the hash-values of (service-lb-dataplane-upgrade-warnings *upgrade-probe-dataplane*)
                   collect message)))
    (assert (= 1 (service-lb-dataplane-upgrade-completed *upgrade-probe-dataplane*)))
    (assert (equal *upgrade-probe-before* (upgrade-probe-snapshot)))
    (destructuring-bind (map-path link-path directory) (upgrade-probe-paths)
      (declare (ignore directory))
      (check-cni-policy *upgrade-probe-configuration* *upgrade-probe-context* map-path link-path)
      (dolist (pin (cni-upgrade-block-paths map-path))
        (assert (not (probe-file pin))) (assert (null (cni-policy-staged-links pin)))))
    (list :passed t :map-and-link-ids-preserved t :gc-enabled t)))

(defun upgrade-probe-guard-ring-id ()
  "The map ID of the flow-event ring the endpoint's egress guard writes to."
  (let ((link (whistler/loader:open-pinned-object
               (concatenate 'string (namestring (third (upgrade-probe-paths))) "tcx-ingress"))))
    (unwind-protect
         (let ((ring (packet-program-flow-ring-fd
                      (netlink-read-integer (bpf-object-kernel-info link) 8 4))))
           (assert ring)
           (unwind-protect (netlink-read-integer (bpf-object-kernel-info ring) 4 4)
             (sb-posix:close ring)))
      (sb-posix:close link))))

(defun upgrade-probe-guard-config-id ()
  "The map ID of the flow-event settings the endpoint's stage programs read."
  (let ((stages (whistler/loader:open-pinned-object
                 (concatenate 'string (namestring (third (upgrade-probe-paths))) "gr8s_pkt_stages"))))
    (unwind-protect
         (let* ((map (cni-policy-map-info stages "gr8s_pkt_stages"))
                (config (packet-program-flow-config-fd
                         (loop for index below 3
                               for value = (whistler/loader:map-lookup map (service-lb-bytes index 4))
                               collect (and value (netlink-read-integer value 0 4))))))
           (assert config)
           (unwind-protect (netlink-read-integer (bpf-object-kernel-info config) 4 4)
             (sb-posix:close config)))
      (sb-posix:close stages))))

(defun upgrade-probe-shared-ring ()
  "Once the node pins its flow-event ring and settings, one refresh moves the guard
onto both and the next finds it current."
  (let* ((path (merge-pathnames "gr8s_pkt_stages" (third (upgrade-probe-paths))))
         (private (upgrade-probe-guard-ring-id))
         (private-config (upgrade-probe-guard-config-id))
         (ring (open-flow-events-ring *upgrade-probe-root* :create t))
         (config (open-flow-config *upgrade-probe-root* :create t))
         (shared (netlink-read-integer (bpf-object-kernel-info (whistler/loader:map-info-fd ring)) 4 4))
         (shared-config (netlink-read-integer (bpf-object-kernel-info (whistler/loader:map-info-fd config)) 4 4)))
    (unwind-protect
         (progn
           (assert (/= private shared))
           (assert (/= private-config shared-config))
           (assert (service-packet-gc-compatible-p *upgrade-probe-dataplane* :paths (constantly (list path))))
           (assert (= 2 (service-lb-dataplane-upgrade-completed *upgrade-probe-dataplane*)))
           (assert (= shared (upgrade-probe-guard-ring-id)))
           (assert (= shared-config (upgrade-probe-guard-config-id)))
           (clrhash (service-lb-dataplane-upgrade-cache *upgrade-probe-dataplane*))
           (assert (service-packet-gc-compatible-p *upgrade-probe-dataplane* :paths (constantly (list path))))
           (assert (= 2 (service-lb-dataplane-upgrade-completed *upgrade-probe-dataplane*)))
           (list :passed t :private-ring private :shared-ring shared
                 :private-config private-config :shared-config shared-config))
      (sb-posix:close (whistler/loader:map-info-fd ring))
      (sb-posix:close (whistler/loader:map-info-fd config))
      (ignore-errors (delete-file (flow-events-pin-path *upgrade-probe-root*)))
      (ignore-errors (delete-file (flow-config-pin-path *upgrade-probe-root*))))))

(defun upgrade-probe-cleanup ()
  (when *upgrade-probe-configuration*
    (destructuring-bind (map-path link-path directory) (upgrade-probe-paths)
      (remove-cni-policy *upgrade-probe-configuration* *upgrade-probe-context* map-path link-path directory)))
  (when *upgrade-probe-dataplane*
    (stop-service-lb-dataplane *upgrade-probe-dataplane* :remove-pins t)
    (setf *upgrade-probe-dataplane* nil))
  (list :passed t :cleanup t))
