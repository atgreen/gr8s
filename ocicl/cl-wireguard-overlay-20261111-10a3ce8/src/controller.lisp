;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-wireguard-overlay)

(defstruct (overlay-controller
             (:constructor make-overlay-controller (&key observe apply)))
  "Adapter-neutral path controller.
OBSERVE returns candidate observations for a peer. APPLY installs a selected
path and receives peer ID, observation, and selection reason."
  observe
  apply
  (selected (make-hash-table :test #'equal)))

(defun overlay-controller-selected-path (controller peer-id)
  "Return CONTROLLER's selected observation for PEER-ID, or NIL."
  (gethash peer-id (overlay-controller-selected controller)))

(defun reconcile-overlay-peer (controller peer-id &key (minimum-successes 3)
                                                        (improvement-ratio 4/5)
                                                        (maximum-handshake-age 180))
  "Observe PEER-ID, conservatively select its path, and apply only a change."
  (let* ((observations (funcall (overlay-controller-observe controller) peer-id))
         (current (overlay-controller-selected-path controller peer-id)))
    (unless observations
      (error "No path observations for peer ~A" peer-id))
    (multiple-value-bind (selected reason)
        (select-wireguard-path current observations
                               :minimum-successes minimum-successes
                               :improvement-ratio improvement-ratio
                               :maximum-handshake-age maximum-handshake-age)
      (unless (eq selected current)
        (funcall (overlay-controller-apply controller) peer-id selected reason)
        (setf (gethash peer-id (overlay-controller-selected controller)) selected))
      (values selected reason))))
