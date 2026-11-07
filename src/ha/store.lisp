;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The replicated desired-state store state machine for the HA control plane
;;;; (podster-c2d.4). API writes become Raft commands; every member applies the
;;;; committed command to its own copy, so all members converge byte-for-byte.
;;;;
;;;; Two correctness requirements shape the command protocol:
;;;;   1. Linearizable optimistic concurrency -- the resourceVersion compare is
;;;;      evaluated at APPLY time against committed state, not at propose time.
;;;;   2. Determinism -- apply must be a pure function of the command, so any
;;;;      nondeterminism the single-node store used (UID generation, wall-clock
;;;;      creationTimestamp) is pre-computed on the leader and carried in the
;;;;      command. Otherwise members would assign different UIDs and diverge.
;;;;
;;;; This is the state machine the leader-aware HTTP/controller wiring
;;;; (podster-c2d.7) proposes into; here it is proven in isolation. The stored
;;;; VALUE is opaque to the state machine (JSON-encoded on the wire).

(in-package #:gr8s.ha)

(defstruct raft-resource-store
  (revision 0 :type fixnum)
  (resources (make-hash-table :test 'equal)))   ; key -> raft-resource-record

(defstruct raft-resource-record uid (resource-version 0 :type fixnum) value)

(defun raft-resource-get (store key)
  "Return the RAFT-RESOURCE-RECORD stored under KEY in STORE, or NIL when absent."
  (gethash key (raft-resource-store-resources store)))

(defun raft-resource-apply (store command)
  "Apply one committed desired-state COMMAND to STORE, returning a result the
   proposing client receives through its Raft callback. Pure in STORE+COMMAND.

   Commands:
     (:put key value :expected RV :uid UID)
        RV = NIL   -> create; fails (:exists ...) if KEY is present
        RV = int   -> update; (:conflict current) unless it matches
     (:delete key :expected RV)"
  (ecase (first command)
    (:put
     (destructuring-bind (key value &key expected uid) (rest command)
       (let ((existing (raft-resource-get store key)))
         (cond
           ((null expected)
            (if existing
                (list :exists (raft-resource-record-resource-version existing))
                (let ((rv (incf (raft-resource-store-revision store))))
                  (setf (gethash key (raft-resource-store-resources store))
                        (make-raft-resource-record :uid uid :resource-version rv :value value))
                  (list :ok rv uid))))
           ((null existing) (list :conflict nil))
           ((= expected (raft-resource-record-resource-version existing))
            (let ((rv (incf (raft-resource-store-revision store))))
              (setf (raft-resource-record-resource-version existing) rv
                    (raft-resource-record-value existing) value)
              (list :ok rv (raft-resource-record-uid existing))))
           (t (list :conflict (raft-resource-record-resource-version existing)))))))
    (:delete
     (destructuring-bind (key &key expected) (rest command)
       (let ((existing (raft-resource-get store key)))
         (cond
           ((null existing) (list :not-found))
           ((and expected (/= expected (raft-resource-record-resource-version existing)))
            (list :conflict (raft-resource-record-resource-version existing)))
           (t (incf (raft-resource-store-revision store))
              (remhash key (raft-resource-store-resources store))
              (list :ok))))))))

(defun raft-resource-store-equal (a b)
  "True when two replicas hold identical state (revision + every record)."
  (and (= (raft-resource-store-revision a) (raft-resource-store-revision b))
       (= (hash-table-count (raft-resource-store-resources a))
          (hash-table-count (raft-resource-store-resources b)))
       (loop for key being the hash-keys of (raft-resource-store-resources a)
               using (hash-value ra)
             for rb = (gethash key (raft-resource-store-resources b))
             always (and rb
                         (equal (raft-resource-record-uid ra) (raft-resource-record-uid rb))
                         (= (raft-resource-record-resource-version ra)
                            (raft-resource-record-resource-version rb))
                         (equal (raft-resource-record-value ra) (raft-resource-record-value rb))))))
