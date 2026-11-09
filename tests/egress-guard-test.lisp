;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove the per-endpoint guards JIT-compile in-process to the policy maps
;;;; and classifier programs the CNI path expects, with no ELF, and guard
;;;; against drift between the in-image source and the legacy standalone source
;;;; until the latter is removed (podster-7q2.5c).

(in-package #:gr8s/tests)
(def-suite egress-guard :in gr8s)
(in-suite egress-guard)

(test service-guard-stages-preserve-the-canonical-policy-program
  (multiple-value-bind (maps programs) (gr8s::compile-egress-guard :service-packets t)
    (multiple-value-bind (plain-maps plain-programs) (gr8s::compile-egress-guard)
      (declare (ignore plain-maps))
      (let ((policy (find "gr8s_egress_policy" programs :test #'equal
                          :key (lambda (program) (getf program :name)))))
        (is (equalp (getf (first plain-programs) :insns) (getf policy :insns)))
        (is (equalp (getf (first plain-programs) :relocs) (getf policy :relocs)))))
    (is (= 27 (length maps)))
    (is (= 5 (length programs)))
    (let ((stages (find "gr8s_pkt_stages" maps :test #'equal :key (lambda (map) (getf map :name)))))
      (is (eq :prog-array (getf stages :type)))
      (is (= 8 (getf stages :max-entries))))))

(test service-guard-requires-shared-maps-and-populates-all-continuations
  (let* ((gr8s.network::*cni-service-packets* t)
         (object (gr8s::compile-egress-policy-object))
         (shared (loop for spec in (gr8s.network::service-packet-map-specs)
                       for fd from 900 collect (cons (first spec) fd)))
         (created nil) (writes nil))
    (signals gr8s::cni-error
      (gr8s::load-egress-policy-object object nil :create-map (lambda (map) (push map created))))
    (is (null created))
    (gr8s::load-egress-policy-object
     object shared
     :create-map (lambda (map) (push (whistler/loader:map-info-name map) created)
                   (setf (whistler/loader:map-info-fd map) (+ 800 (length created))) map)
     :load-programs
     (lambda (specs maps)
       (declare (ignore maps))
       (loop for spec in specs for fd from 1001
             collect (cons (getf spec :name)
                           (whistler/loader::make-prog-info
                            :name (getf spec :name) :fd fd :type 3
                            :section-name "classifier" :insns #()))))
     :update (lambda (map key value)
               (push (list (whistler/loader:map-info-name map) key value) writes)))
    (is (= 17 (length created)))
    (dolist (entry shared) (is (not (member (car entry) created :test #'equal))))
    (is (equalp (list (list "gr8s_pkt_stages" #(0 0 0 0) (gr8s::service-lb-bytes 1004 4))
                     (list "gr8s_pkt_stages" #(1 0 0 0) (gr8s::service-lb-bytes 1003 4))
                     (list "gr8s_pkt_stages" #(2 0 0 0) (gr8s::service-lb-bytes 1005 4)))
                (nreverse writes)))))

(defun egress-map-spec (specs name)
  (find name specs :key (lambda (s) (getf s :name)) :test #'string=))

(test egress-guard-compiles-in-process-to-the-policy-maps
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-egress-guard)
    ;; The maps the CNI pins, with the schemas endpoint-policy checks: the three guard
    ;; maps, the NetworkPolicy maps the agent writes, and the redirect tables.
    (is (= (length gr8s::+cni-policy-map-specs+) (length map-specs)))
    (loop for (name type key-size value-size max-entries flags) in gr8s::+cni-policy-map-specs+
          for spec = (egress-map-spec map-specs name)
          do (is (and spec
                      (= type (whistler/compiler:resolve-map-type (getf spec :type)))
                      (= key-size (getf spec :key-size)) (= value-size (getf spec :value-size))
                      (= max-entries (getf spec :max-entries)) (= flags (or (getf spec :flags) 0)))
                 "~A does not match the CNI's schema" name))
    ;; Two TC classifiers over those maps: the egress guard and the ingress guard, with
    ;; real, 8-byte-aligned instructions and the map-fd relocations the loader patches in.
    (is (equal '("gr8s_egress_guard" "gr8s_ingress_guard") (mapcar (lambda (spec) (getf spec :name)) prog-specs)))
    (dolist (spec prog-specs)
      (let ((insns (getf spec :insns)))
        (is (string= "classifier" (getf spec :section)))
        (is (plusp (length insns)))
        (is (zerop (mod (length insns) 8)))
        (is (>= (length (getf spec :relocs)) 3))))))

(test egress-guard-publishes-ipv6-policy-and-flow-maps
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-egress-guard)
    (declare (ignore prog-specs))
    (dolist (expected '("netpol_egress_cidr_v6" "netpol_ingress_cidr_v6"
                        "netpol_egress_ports_v6" "netpol_ingress_ports_v6"
                        "netpol_flows_v6"))
      (is (egress-map-spec map-specs expected) "missing ~A" expected))
    (let ((egress (egress-map-spec map-specs "netpol_egress_cidr_v6"))
          (flows (egress-map-spec map-specs "netpol_flows_v6")))
      (is (= 20 (getf egress :key-size)))
      (is (= 24 (getf flows :key-size))))))

;;; In-process policy object for the CNI installer.  create-map and the program
;;; loader are injected, so the create/reuse/load orchestration runs rootless.

(test egress-guard-dns-redirect-constant-tracks-the-node-dns-address
  ;; The guard's DNS redirect-to-lo clause hardcodes the node gateway/DNS
  ;; address as a BPF constant (#xa9fe0101). If the Lisp address ever changes,
  ;; this fails loudly so the program constant is updated in lockstep.
  (is (string= "169.254.1.1" gr8s::+dns-pod-server-address+))
  (is (= #xa9fe0101 (gr8s::parse-ipv4-integer gr8s::+dns-pod-server-address+))))

(test egress-policy-object-reuses-pinned-maps-and-creates-the-rest
  (let ((object (gr8s::compile-egress-policy-object "/ignored/path.o"))
        (created nil) (loaded-with nil))
    (gr8s::load-egress-policy-object
     object
     ;; endpoint_identity is already pinned (fd 555); the others are created.
     '(("endpoint_identity" . 555))
     :create-map (lambda (info)
                   (push (whistler/loader:map-info-name info) created)
                   (setf (whistler/loader:map-info-fd info) 900)
                   info)
     :load-programs (lambda (specs maps)
                      (declare (ignore specs))
                      (setf loaded-with maps)
                      (loop for (name fd) in '(("gr8s_egress_guard" 901) ("gr8s_ingress_guard" 902))
                            collect (cons name (whistler/loader::make-prog-info
                                                :name name :section-name "classifier"
                                                :type 3 :insns #() :fd fd)))))
    ;; Every map except the reused endpoint_identity was created.
    (is (= (1- (length gr8s::+cni-policy-map-specs+)) (length created)))
    (is (not (member "endpoint_identity" created :test #'string=)))
    (is (member "rejected_spoofs" created :test #'string=))
    (is (member "traffic_stats" created :test #'string=))
    (is (member "netpol_egress_cidr" created :test #'string=))
    (is (member "netpol_flows" created :test #'string=))
    (is (member "host_redirect_v4" created :test #'string=))
    ;; The reused map keeps its pinned fd; both programs load against every map.
    (is (= 555 (whistler/loader:map-info-fd
                (gr8s::egress-policy-object-find-map object "endpoint_identity"))))
    (is (= (length gr8s::+cni-policy-map-specs+) (length loaded-with)))
    (is (= 901 (whistler/loader:prog-info-fd
                (gr8s::egress-policy-object-find-program object "gr8s_egress_guard"))))
    (is (= 902 (whistler/loader:prog-info-fd
                (gr8s::egress-policy-object-find-program object "gr8s_ingress_guard"))))))

;; podster-uqb.97: this took 0.53s of the 0.58s of agent CNI handling for each Pod.
(test egress-policy-objects-compile-the-guard-once
  (let ((saved gr8s::*egress-guard-specs*)
        (compiles 0))
    (setf gr8s::*egress-guard-specs* nil)
    (sb-int:encapsulate 'gr8s::compile-egress-guard 'count-compiles
                        (lambda (function &rest arguments)
                          (incf compiles)
                          (apply function arguments)))
    (unwind-protect
         (let* ((threads (loop repeat 4
                               collect (bt:make-thread #'gr8s::compile-egress-policy-object)))
                (objects (mapcar #'bt:join-thread threads)))
           (is (= 1 compiles))
           (is (eq (gr8s::egress-policy-object-program-specs (first objects))
                   (gr8s::egress-policy-object-program-specs (second objects))))
           ;; Each Pod still gets its own object for its own map and program fds.
           (is (not (eq (first objects) (second objects))))
           (is (plusp (length (gr8s::egress-policy-object-map-specs (first objects))))))
      (sb-int:unencapsulate 'gr8s::compile-egress-guard 'count-compiles)
      (setf gr8s::*egress-guard-specs* saved))))

(test egress-policy-object-close-releases-all-fds
  (let ((object (gr8s::compile-egress-policy-object))
        (closed nil))
    (gr8s::load-egress-policy-object
     object '()
     :create-map (lambda (info) (setf (whistler/loader:map-info-fd info) 900) info)
     :load-programs (lambda (specs maps) (declare (ignore specs maps))
                      (loop for (name fd) in '(("gr8s_egress_guard" 901) ("gr8s_ingress_guard" 902))
                            collect (cons name (whistler/loader::make-prog-info
                                                :name name :section-name "classifier"
                                                :type 3 :insns #() :fd fd)))))
    (gr8s::close-egress-policy-object object :close-fd (lambda (fd) (push fd closed)))
    ;; Both program fds and every map fd are closed.
    (is (member 901 closed))
    (is (member 902 closed))
    (is (= (+ 2 (length gr8s::+cni-policy-map-specs+)) (length closed)))))

(test service-guard-can-load-replacements-without-publishing-live-stages
  (let* ((map-spec '(:name "gr8s_pkt_stages" :type :prog-array :key-size 4
                    :value-size 4 :max-entries 8 :flags 0))
         (names '("gr8s_packet_forward" "gr8s_egress_policy" "gr8s_packet_reverse"))
         (object (gr8s.network::%make-egress-policy-object (list map-spec) nil))
         (writes nil))
    (gr8s.network::load-egress-policy-object
     object '(("gr8s_pkt_stages" . 900101)) :publish-stages nil
     :create-map (lambda (map) (declare (ignore map)) (error "must reuse the pinned table"))
     :load-programs (lambda (specs maps)
                      (declare (ignore specs maps))
                      (loop for name in names for fd from 900102
                            collect (cons name (whistler/loader::make-prog-info :fd fd))))
     :update (lambda (&rest values) (push values writes)))
    (is (null writes))
    (is (= 900101 (whistler/loader:map-info-fd
                  (gr8s.network::egress-policy-object-find-map object "gr8s_pkt_stages"))))
    (gr8s.network::publish-egress-policy-stages
     object :update (lambda (map key value)
                      (declare (ignore map)) (push (list key value) writes)))
    (is (equalp (loop for fd from 900102 to 900104 for index from 0
                     collect (list (gr8s::service-lb-bytes index 4) (gr8s::service-lb-bytes fd 4)))
                (nreverse writes)))
    (setf writes nil
          (gr8s.network::egress-policy-object-programs object)
          (butlast (gr8s.network::egress-policy-object-programs object)))
    (signals gr8s::cni-error
      (gr8s.network::publish-egress-policy-stages
       object :update (lambda (&rest values) (push values writes))))
    (is (null writes))))

(test packet-upgrade-syscalls-bind-to-the-owned-tcx-link
  (dolist (direction '(46 47))
    (let ((info (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
      (whistler/loader::put-u32 info 0 11)
      (whistler/loader::put-u32 info 16 71)
      (whistler/loader::put-u32 info 20 direction)
      (is (= 900203
             (gr8s.network::attach-packet-upgrade-blocker
              900201 900202 :object-info (constantly info)
              :bpf (lambda (command attribute size context)
                     (declare (ignore context))
                     (is (= 28 command)) (is (= 32 size))
                     (is (equal '(900201 71 8 0)
                                (mapcar (lambda (offset) (gr8s::netlink-read-integer attribute offset 4))
                                        '(0 4 12 16))))
                     (is (= direction (gr8s::netlink-read-integer attribute 8 4)))
                     900203))))
      (whistler/loader::put-u32 info 0 1)
      (signals gr8s::cni-error
        (gr8s.network::attach-packet-upgrade-blocker
         900201 900202 :object-info (constantly info) :bpf (lambda (&rest ignored)
                                  (declare (ignore ignored)) (error "must not attach"))))))
  (gr8s.network::replace-packet-tcx-program
   900211 900212 900213
   :bpf (lambda (command attribute size context)
          (declare (ignore context))
          (is (= 29 command)) (is (= 16 size))
          (is (equal '(900211 900212 4 900213)
                     (loop for offset from 0 below 16 by 4
                           collect (gr8s::netlink-read-integer attribute offset 4)))))))

(test packet-upgrade-interruptions-never-unblock-unverified-pipelines
  ;; Interrupt after every externally visible mutation, including after one
  ;; guard has been removed. Preparation/loading happens before this protocol.
  (loop for interrupt from 0 to 8
        do (let* ((links (list (list :direction "ingress") (list :direction "egress")))
                  (blocked (make-hash-table :test #'equal))
                  (switched (make-hash-table :test #'equal))
                  (published nil) (verified nil) (step -1))
             (labels ((checkpoint () (when (= (incf step) interrupt) (error "injected interruption")))
                      (all-blocked-p () (every (lambda (link) (gethash (getf link :direction) blocked)) links))
                      (upgrade ()
                        (gr8s.network::perform-service-packet-upgrade
                         :prepared links
                         :block (lambda (link)
                                  (setf (gethash (getf link :direction) blocked) t) (checkpoint))
                         :publish (lambda (object)
                                    (is (eq :prepared object)) (is-true (all-blocked-p))
                                    (setf published t) (checkpoint))
                         :switch (lambda (link object)
                                   (declare (ignore object))
                                   (is-true (all-blocked-p)) (is-true published)
                                   (setf (gethash (getf link :direction) switched) t) (checkpoint))
                         :verify (lambda (actual object)
                                   (declare (ignore actual object))
                                   (is-true (all-blocked-p)) (is (= 2 (hash-table-count switched)))
                                   (setf verified t) (checkpoint) t)
                         :unblock (lambda (link)
                                    (is-true verified)
                                    (remhash (getf link :direction) blocked) (checkpoint)))))
               (if (< interrupt 8) (signals simple-error (upgrade)) (is-true (upgrade)))
               (cond ((< interrupt 2) (is-false published) (is (zerop (hash-table-count switched))))
                     ((< interrupt 6) (is (= 2 (hash-table-count blocked))))
                     ((= interrupt 6) (is (= 1 (hash-table-count blocked))) (is-true verified))
                     (t (is (zerop (hash-table-count blocked))) (is-true verified)))))))

(test packet-upgrade-budget-defers-gc-and-makes-progress-after-an-endpoint-fails
  (let* ((dataplane (gr8s::%make-service-lb-dataplane :pin-directory "/pins/service-lb/"))
         (paths '(#P"/pins/a/gr8s_pkt_stages" #P"/pins/b/gr8s_pkt_stages" #P"/pins/c/gr8s_pkt_stages"))
         (calls nil) (broken t) (*error-output* (make-string-output-stream)))
    (labels ((refresh (directory root cache allow-load)
               (is (equal "/pins/service-lb/" root))
               (let ((key (namestring directory)))
                 (push key calls)
                 (cond ((gethash key cache) :current)
                       ((not (funcall allow-load)) :pending)
                       ((and broken (equal key "/pins/a/")) (error "injected legacy failure"))
                       (t (setf (gethash key cache) t) :refreshed)))))
      (is-false (gr8s.network::refresh-service-packet-pipelines dataplane paths :budget 2 :refresh #'refresh))
      (is (gethash "/pins/b/" (gr8s::service-lb-dataplane-upgrade-cache dataplane)))
      (is-false (gethash "/pins/c/" (gr8s::service-lb-dataplane-upgrade-cache dataplane)))
      (is (= 1 (gr8s::service-lb-dataplane-upgrade-completed dataplane)))
      (is (search "injected legacy failure" (get-output-stream-string *error-output*)))
      (is-false (gr8s.network::refresh-service-packet-pipelines dataplane paths :budget 2 :refresh #'refresh))
      (is (gethash "/pins/c/" (gr8s::service-lb-dataplane-upgrade-cache dataplane)))
      (is-false (search "injected legacy failure" (get-output-stream-string *error-output*)))
      (setf broken nil)
      (is-true (gr8s.network::refresh-service-packet-pipelines dataplane paths :budget 2 :refresh #'refresh))
      (is (= 3 (gr8s::service-lb-dataplane-upgrade-completed dataplane)))
      (is (zerop (hash-table-count (gr8s::service-lb-dataplane-upgrade-warnings dataplane))))
      (is-true (gr8s.network::refresh-service-packet-pipelines dataplane (rest paths) :budget 1 :refresh #'refresh))
      (is-false (gethash "/pins/a/" (gr8s::service-lb-dataplane-upgrade-cache dataplane)))
      (is (= 3 (gr8s::service-lb-dataplane-upgrade-completed dataplane))))))
