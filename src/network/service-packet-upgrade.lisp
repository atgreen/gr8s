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
    (program-fd link-fd link-info &key (bpf #'whistler/loader::%bpf))
  "Insert a blocker BEFORE the owned TCX link. The caller pins the returned FD.
Insertion swaps the TCX multiprogram array and waits for its RCU readers, so
return also drains executions that started before this direction was blocked.
Linux6.19: kernel/bpf/tcx.c tcx_link_prog_attach and include/net/tcx.h tcx_entry_sync.
Must run in the endpoint's network namespace. Replacement alone does not drain."
  (unless (and (>= (length link-info) 24)
               (= 11 (netlink-read-integer link-info 0 4))
               (plusp (netlink-read-integer link-info 16 4))
               (member (netlink-read-integer link-info 20 4) '(46 47)))
    (invalid-cni "cannot quiesce an invalid TCX link"))
  (let ((attribute (whistler/loader::make-attr-buf)))
    (whistler/loader::put-u32 attribute 0 program-fd)
    (whistler/loader::put-u32 attribute 4 (netlink-read-integer link-info 16 4))
    (whistler/loader::put-u32 attribute 8 (netlink-read-integer link-info 20 4))
    (whistler/loader::put-u32 attribute 12 (logior 8 8192)) ; BEFORE | LINK
    (whistler/loader::put-u32 attribute 16 link-fd) ; relative_fd, not program fd
    (funcall bpf 28 attribute 32 "quiesce packet endpoint")))

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
