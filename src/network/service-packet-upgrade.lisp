;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Retained packet pipeline upgrades. Preparation must not publish into a live
;;;; table; legacy writers are quiesced before stage publication and link updates.

(in-package #:gr8s.network)

(defun packet-program-fd-by-id (identity)
  "Hold the actual program alive while comparing or replacing a retained stage."
  (let ((attribute (whistler/loader::make-attr-buf)))
    (whistler/loader::put-u32 attribute 0 identity)
    (whistler/loader::%bpf 13 attribute 12 "packet program by ID")))

(defun packet-program-signature (fd)
  "Compare kernel bytecode tags and actual map IDs, never program display names."
  (let ((info (bpf-object-kernel-info fd)))
    (list (netlink-read-integer info 0 4)
          (subseq info 8 16)
          (sort (packet-program-map-ids (netlink-read-integer info 4 4)) #'<))))

(defun load-packet-upgrade-blocker ()
  "Load a map-free classifier that drops every frame during a legacy upgrade."
  (whistler/loader::load-program
   (make-array 16 :element-type '(unsigned-byte 8)
                 :initial-contents '(#xb7 0 0 0 2 0 0 0 #x95 0 0 0 0 0 0 0))
   3 "GPL"))

(defun attach-packet-upgrade-blocker
    (program-fd link-fd &key (object-info #'bpf-object-kernel-info) (bpf #'whistler/loader::%bpf))
  "Prepend a blocker on the owned TCX interface. The caller pins the returned FD.
Prepending also blocks old entries whose pins were removed before deferred release.
Insertion swaps the TCX multiprogram array and waits for its RCU readers, so
return also drains executions that started before this direction was blocked.
Linux6.19: kernel/bpf/tcx.c tcx_link_prog_attach and include/net/tcx.h tcx_entry_sync.
Must run in the endpoint's network namespace. Replacement alone does not drain."
  (let ((link-info (funcall object-info link-fd)))
  (unless (and (>= (length link-info) 24)
               (= 11 (netlink-read-integer link-info 0 4))
               (plusp (netlink-read-integer link-info 16 4))
               (member (netlink-read-integer link-info 20 4) '(46 47)))
    (invalid-cni "cannot quiesce an invalid TCX link"))
  (let ((attribute (whistler/loader::make-attr-buf)))
    (whistler/loader::put-u32 attribute 0 program-fd)
    (whistler/loader::put-u32 attribute 4 (netlink-read-integer link-info 16 4))
    (whistler/loader::put-u32 attribute 8 (netlink-read-integer link-info 20 4))
    (whistler/loader::put-u32 attribute 12 8) ; BEFORE with no relative_fd: first entry
    (funcall bpf 28 attribute 32 "quiesce packet endpoint"))))

(defun packet-tcx-program-ids (link-info)
  "Read the actual TCX chain, including attached entries that no longer have pins."
  (let ((attribute (whistler/loader::make-attr-buf))
        (identities (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    (whistler/loader::put-u32 attribute 0 (netlink-read-integer link-info 16 4))
    (whistler/loader::put-u32 attribute 4 (netlink-read-integer link-info 20 4))
    (whistler/loader::put-u32 attribute 24 64)
    (sb-sys:with-pinned-objects (identities)
      (whistler/loader::put-ptr attribute 16 (sb-sys:vector-sap identities))
      (whistler/loader::%bpf 16 attribute 64 "packet TCX chain"))
    (let ((count (netlink-read-integer attribute 24 4)))
      (unless (<= count 64) (invalid-cni "TCX program chain exceeds reader capacity"))
      (loop for index below count collect (netlink-read-integer identities (* index 4) 4)))))

(defun replace-packet-tcx-program
    (link-fd new-program-fd old-program-fd &key (bpf #'whistler/loader::%bpf))
  "CAS-replace the owned link's program, preserving link identity and attachment.
This is called only after both directions have pinned, drained drop guards."
  (let ((attribute (whistler/loader::make-attr-buf)))
    (whistler/loader::put-u32 attribute 0 link-fd)
    (whistler/loader::put-u32 attribute 4 new-program-fd)
    (whistler/loader::put-u32 attribute 8 4) ; BPF_F_REPLACE
    (whistler/loader::put-u32 attribute 12 old-program-fd)
    (funcall bpf 29 attribute 16 "replace packet endpoint program")))

(defun perform-service-packet-upgrade
    (object links &key block (publish #'publish-egress-policy-stages) switch verify unblock)
  "Publish prepared programs only behind two drained blockers. Failure retains
any pinned blockers; recovery retries from authoritative kernel/pin state.
No error path unblocks an endpoint with mixed or unverified continuations."
  (unless (and (= 2 (length links))
               (equal '("egress" "ingress")
                      (sort (mapcar (lambda (link) (getf link :direction)) links) #'string<))
               (every #'functionp (list block publish switch verify unblock)))
    (invalid-cni "incomplete packet upgrade operations"))
  (dolist (link links) (funcall block link))
  (funcall publish object)
  (dolist (link links) (funcall switch link object))
  (unless (funcall verify links object)
    (invalid-cni "packet upgrade kernel verification failed"))
  (dolist (link links) (funcall unblock link))
  t)

(defun load-packet-upgrade-programs (specs maps)
  "Close an already-loaded prefix if a later replacement fails verification."
  (let ((programs nil) (complete nil))
    (unwind-protect
         (progn
           (dolist (spec specs)
             (setf programs (nconc programs (whistler/loader::session-load-progs (list spec) maps))))
           (setf complete t)
           programs)
      (unless complete
        (dolist (program programs)
          (ignore-errors (sb-posix:close (whistler/loader:prog-info-fd (cdr program)))))))))

(defun refresh-service-packet-endpoint (directory shared-root cache allow-load)
  "Refresh one native endpoint using its actual pinned programs and map schemas.
CACHE is per-agent and checked against live link/stage IDs on every visit.
ALLOW-LOAD bounds expensive preparations per tick. Return :CURRENT, :REFRESHED
or :PENDING. Errors leave pinned blockers intact and must keep GC deferred."
  (let* ((directory (uiop:ensure-directory-pathname directory))
         (cache-key (namestring directory))
         (owned-fds nil) (object nil))
    (labels ((own (fd) (push fd owned-fds) fd)
             (open-pin (path) (own (whistler/loader:open-pinned-object (namestring path))))
             (info (fd) (bpf-object-kernel-info fd))
             (program-id (fd) (netlink-read-integer (info fd) 4 4))
             (program-fd (identity) (own (packet-program-fd-by-id identity)))
             (stage-ids (map)
               (loop for index below 3
                     for value = (whistler/loader:map-lookup map (service-lb-bytes index 4))
                     collect (and value (netlink-read-integer value 0 4))))
             (block-pins (path)
               (append (when (probe-file path) (list path)) (cni-policy-staged-links (namestring path)))))
      (unwind-protect
           (let* ((stage-fd (open-pin (merge-pathnames "gr8s_pkt_stages" directory)))
                  (stage-map (cni-policy-map-info stage-fd "gr8s_pkt_stages"))
                  (links
                    (loop for direction in '("ingress" "egress")
                          for name in '("gr8s_egress_guard" "gr8s_ingress_guard")
                          for path = (merge-pathnames (concatenate 'string "tcx-" direction) directory)
                          for fd = (open-pin path)
                          for metadata = (info fd)
                          for index = (netlink-read-integer metadata 16 4)
                          do (check-cni-tcx-link fd index direction)
                             (unless (plusp index) (invalid-cni "retained endpoint TCX link is detached"))
                          collect (list :direction direction :program-name name :path path :fd fd
                                        :info metadata :index index :old-program-fd nil
                                        :block-path (merge-pathnames
                                                     (concatenate 'string "gr8s_pkt_upgrade_" direction)
                                                     directory)))))
             (unless (= (getf (first links) :index) (getf (second links) :index))
               (invalid-cni "retained endpoint TCX directions name different interfaces"))
             (labels ((fingerprint ()
                        (list (loop for link in links
                                    for metadata = (info (getf link :fd))
                                    collect (list (netlink-read-integer metadata 4 4)
                                                  (netlink-read-integer metadata 8 4)))
                              (netlink-read-integer (info stage-fd) 4 4)
                              (stage-ids stage-map)))
                      (blocked-p () (some (lambda (link) (block-pins (getf link :block-path))) links))
                      (entry-programs-first-p ()
                        (every (lambda (link)
                                 (eql (first (packet-tcx-program-ids (getf link :info)))
                                      (netlink-read-integer (info (getf link :fd)) 8 4))) links)))
               (let ((before (fingerprint)))
                 (when (and (not (blocked-p)) (entry-programs-first-p)
                            (equal before (gethash cache-key cache)))
                   (return-from refresh-service-packet-endpoint :current))
                 (unless (funcall allow-load)
                   (return-from refresh-service-packet-endpoint :pending))
                 (let ((replacements (list (cons "gr8s_pkt_stages" stage-fd))))
                   (dolist (spec +cni-policy-map-specs+)
                     (let* ((name (first spec)) (fd (open-pin (merge-pathnames name directory))))
                       (cni-policy-map-info fd name)
                       (push (cons name fd) replacements)))
                   ;; Shared descriptors are separately opened, not borrowed
                   ;; from the dataplane that the collector/controller owns.
                   (dolist (spec (service-packet-map-specs))
                     (let* ((name (first spec))
                            (fd (open-pin (merge-pathnames name (uiop:ensure-directory-pathname shared-root)))))
                       (cni-policy-map-info fd name)
                       (push (cons name fd) replacements)))
                   (let* ((identity (cni-policy-map-info (cdr (assoc "endpoint_identity" replacements
                                                                   :test #'equal)) "endpoint_identity"))
                          (value (whistler/loader:map-lookup identity (service-lb-bytes 0 4))))
                     (unless (and value (= +cni-policy-native-attachment+
                                           (netlink-read-integer value 12 4)))
                       (invalid-cni "automatic packet upgrade requires a native endpoint attachment")))
                   (let ((*cni-service-packets* t))
                     (setf object (compile-egress-policy-object)))
                   (load-egress-policy-object
                    object replacements :publish-stages nil :load-programs #'load-packet-upgrade-programs
                    :create-map (lambda (map)
                                  (invalid-cni "retained endpoint is missing pinned map ~A"
                                               (whistler/loader:map-info-name map))))
                   (dolist (program (egress-policy-object-programs object))
                     (own (whistler/loader:prog-info-fd (cdr program)))))
                 (dolist (link links)
                   (setf (getf link :old-program-fd)
                         (program-fd (netlink-read-integer (getf link :info) 8 4))))
                 (flet ((replacement (name)
                          (whistler/loader:prog-info-fd (egress-policy-object-find-program object name))))
                   (when (and (not (blocked-p)) (entry-programs-first-p)
                              (every (lambda (link)
                                       (equalp (packet-program-signature (getf link :old-program-fd))
                                               (packet-program-signature
                                                (replacement (getf link :program-name))))) links)
                              (loop for id in (third before)
                                    for name in '("gr8s_packet_forward" "gr8s_egress_policy" "gr8s_packet_reverse")
                                    always (and id (plusp id)
                                                (equalp (packet-program-signature (program-fd id))
                                                        (packet-program-signature (replacement name))))))
                     (setf (gethash cache-key cache) before)
                     (return-from refresh-service-packet-endpoint :current))
                   (let* ((drop-fd (own (load-packet-upgrade-blocker)))
                          (drop-signature (packet-program-signature drop-fd))
                          (block-program-ids (list (program-id drop-fd))))
                     ;; Validate prior interruption pins before replacing or
                     ;; removing them. Keep their descriptors alive until exit.
                     (dolist (link links)
                       (dolist (path (block-pins (getf link :block-path)))
                         (let* ((fd (open-pin path)) (metadata (info fd)))
                           (check-cni-tcx-link fd (getf link :index) (getf link :direction))
                           (pushnew (netlink-read-integer metadata 8 4) block-program-ids)
                           (unless (equalp drop-signature
                                           (packet-program-signature
                                            (program-fd (netlink-read-integer metadata 8 4))))
                             (invalid-cni "unrecognized packet upgrade blocker ~A" path)))))
                     (perform-service-packet-upgrade
                      object links
                      :publish
                      (lambda (prepared)
                        ;; Old CNI ADD staging links can remain attached behind
                        ;; a canonical guard. Both directions are blocked now.
                        (let ((allowed-maps
                                (loop for map in (egress-policy-object-maps object)
                                      collect (netlink-read-integer
                                               (info (whistler/loader:map-info-fd (cdr map))) 4 4))))
                          (dolist (link links)
                            (dolist (path (cni-policy-staged-links (namestring (getf link :path))))
                              (let* ((fd (open-pin path)) (metadata (info fd))
                                     (map-ids (packet-program-map-ids (netlink-read-integer metadata 8 4))))
                                (check-cni-tcx-link fd (getf link :index) (getf link :direction))
                                (unless (and map-ids (subsetp map-ids allowed-maps))
                                  (invalid-cni "unrecognized staged endpoint program ~A" path))
                                (detach-cni-tcx-link fd)
                                (remove-cni-path path)))))
                        (publish-egress-policy-stages prepared))
                      :block
                      (lambda (link)
                        ;; A fresh insertion drains readers even when resuming
                        ;; a previous blocker; LINK_UPDATE alone has no grace period.
                        (let* ((path (getf link :block-path))
                               (stage (format nil "~A_pending_~36R" path (random (expt 36 12))))
                               (fd (own (attach-packet-upgrade-blocker
                                         drop-fd (getf link :fd)))))
                          (whistler/loader:pin-bpf-object fd stage)
                          (uiop:rename-file-overwriting-target stage path)))
                      :switch
                      (lambda (link prepared)
                        (declare (ignore prepared))
                        (replace-packet-tcx-program (getf link :fd)
                                                   (replacement (getf link :program-name))
                                                   (getf link :old-program-fd)))
                      :verify
                      (lambda (actual prepared)
                        (declare (ignore actual prepared))
                        (and
                         (every
                          (lambda (link)
                            ;; A concurrent/out-of-agent replacement of a pin
                            ;; cannot make us unblock a different owned link.
                            (let ((pinned (info (open-pin (getf link :path))))
                                  (held (info (getf link :fd))))
                              (check-cni-tcx-link (getf link :fd) (getf link :index) (getf link :direction))
                              (and (= (netlink-read-integer pinned 4 4)
                                      (netlink-read-integer held 4 4))
                                   (= (netlink-read-integer held 8 4)
                                      (program-id (replacement (getf link :program-name))))))) links)
                         (every (lambda (link)
                                  (let* ((expected (program-id (replacement (getf link :program-name))))
                                         (chain (packet-tcx-program-ids (getf link :info)))
                                         (position (position expected chain)))
                                    ;; The canonical guard terminates TCX processing;
                                    ;; only our drop guards may precede it. Later
                                    ;; programs cannot bypass it or mutate flow state.
                                    (and position
                                         (every (lambda (id) (member id block-program-ids))
                                                (subseq chain 0 position))))) links)
                         (equal (stage-ids stage-map)
                                (mapcar (lambda (name) (program-id (replacement name)))
                                        '("gr8s_packet_forward" "gr8s_egress_policy" "gr8s_packet_reverse")))))
                      :unblock
                      (lambda (link)
                        (dolist (path (block-pins (getf link :block-path)))
                          (remove-cni-path path))))
                     (setf (gethash cache-key cache) (fingerprint))
                     :refreshed)))))
        (dolist (fd (remove-duplicates owned-fds)) (ignore-errors (sb-posix:close fd)))))))

(defun refresh-service-packet-pipelines
    (dataplane paths &key (budget 8) (refresh #'refresh-service-packet-endpoint))
  "Verify retained pipelines each tick, preparing at most BUDGET changed endpoints.
Pending or failed endpoints keep collection deferred. Serialize each endpoint
with agent CNI ADD/DEL, allowing other endpoints to make progress after a failure."
  (check-type budget (integer 1 65536))
  (let ((cache (service-lb-dataplane-upgrade-cache dataplane))
        (warnings (service-lb-dataplane-upgrade-warnings dataplane))
        (remaining budget) (ready t) (seen nil))
    (dolist (path paths)
      (let* ((directory (uiop:pathname-directory-pathname path))
             (key (namestring directory)))
        (push key seen)
        (handler-case
            (let ((result
                    (bt:with-lock-held (*cni-policy-update-lock*)
                      (funcall refresh directory (service-lb-dataplane-pin-directory dataplane) cache
                               (lambda () (when (plusp remaining) (decf remaining) t))))))
              (case result
                (:refreshed
                 (incf (service-lb-dataplane-upgrade-completed dataplane))
                 (format *error-output* "gr8s: Service packet pipeline refreshed ~A~%" directory))
                (:current nil)
                (:pending (setf ready nil))
                (otherwise (error "Unexpected packet upgrade result ~S" result)))
              (remhash key warnings))
          (error (condition)
            (setf ready nil)
            (let ((message (princ-to-string condition)))
              (unless (equal message (gethash key warnings))
                (format *error-output* "gr8s: Service packet upgrade deferred for ~A: ~A~%" directory condition)
                (setf (gethash key warnings) message)))))))
    (dolist (table (list cache warnings))
      (loop for key being the hash-keys of table
            unless (member key seen :test #'equal) do (remhash key table)))
    ready))
