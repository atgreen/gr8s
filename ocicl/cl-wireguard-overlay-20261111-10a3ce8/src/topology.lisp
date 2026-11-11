;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-wireguard-overlay)

(defstruct overlay-node name (region "unknown-region") (zone "unknown-zone"))

(defstruct wireguard-topology-plan
  mode
  adjacency
  nodes
  transit-nodes
  object)

(defun node-network-domain (node)
  "Return NODEs region and zone with explicit fallbacks."
  (values (or (overlay-node-region node) "unknown-region")
          (or (overlay-node-zone node) "unknown-zone")))

(defun node-network-link-cost (left right)
  "Return the planner's bounded locality cost between LEFT and RIGHT."
  (multiple-value-bind (left-region left-zone) (node-network-domain left)
    (multiple-value-bind (right-region right-zone) (node-network-domain right)
      (cond ((and (string= left-region right-region)
                  (string= left-zone right-zone)) 1)
            ((string= left-region right-region) 10)
            (t 100)))))

(defun topology-group-push (table key value)
  (push value (gethash key table))
  table)

(defun wireguard-topology-add-edge (adjacency left right cost kind)
  (unless (string= left right)
    (flet ((add-one (source destination)
             (let* ((neighbors (or (gethash source adjacency)
                                   (setf (gethash source adjacency)
                                         (make-hash-table :test #'equal))))
                    (existing (gethash destination neighbors)))
               (when (or (null existing) (< cost (first existing)))
                 (setf (gethash destination neighbors) (list cost kind))))))
      (add-one left right)
      (add-one right left)))
  adjacency)

(defun wireguard-topology-add-ring (adjacency names cost kind)
  (let ((names (sort (remove-duplicates (copy-list names) :test #'string=) #'string<)))
    (cond
      ((= 2 (length names))
       (wireguard-topology-add-edge adjacency (first names) (second names) cost kind))
      ((> (length names) 2)
       (loop for tail on names
             for left = (first tail)
             for right = (or (second tail) (first names))
             do (wireguard-topology-add-edge adjacency left right cost kind)))))
  adjacency)

(defun wireguard-topology-neighbors (plan node-name)
  "Return NODE-NAME's directly authenticated peers in deterministic order."
  (let ((neighbors (gethash node-name (wireguard-topology-plan-adjacency plan))))
    (when neighbors
      (sort (loop for name being the hash-keys of neighbors collect name) #'string<))))

(defun wireguard-topology-next-hop (plan source destination)
  "Return the deterministic weighted-shortest first hop from SOURCE to DESTINATION."
  (when (string= source destination)
    (return-from wireguard-topology-next-hop source))
  (let ((distance (make-hash-table :test #'equal))
        (first-hop (make-hash-table :test #'equal))
        (visited (make-hash-table :test #'equal))
        (names (sort (loop for name being the hash-keys of
                           (wireguard-topology-plan-nodes plan) collect name)
                     #'string<)))
    (setf (gethash source distance) 0)
    (loop
      (let ((current
              (first
               (sort (remove-if (lambda (name)
                                  (or (gethash name visited)
                                      (null (gethash name distance))))
                                (copy-list names))
                     (lambda (left right)
                       (let ((left-distance (gethash left distance))
                             (right-distance (gethash right distance)))
                         (or (< left-distance right-distance)
                             (and (= left-distance right-distance)
                                  (string< left right)))))))))
        (unless current (return nil))
        (when (string= current destination)
          (return (gethash current first-hop)))
        (setf (gethash current visited) t)
        (let ((neighbors
                (and (or (string= current source)
                         (gethash current
                                  (wireguard-topology-plan-transit-nodes plan)))
                     (gethash current (wireguard-topology-plan-adjacency plan)))))
          (when neighbors
            (maphash
             (lambda (neighbor edge)
               (let* ((candidate-distance (+ (gethash current distance) (first edge)))
                      (candidate-hop (if (string= current source)
                                         neighbor (gethash current first-hop)))
                      (known-distance (gethash neighbor distance))
                      (known-hop (gethash neighbor first-hop)))
                 (when (or (null known-distance)
                           (< candidate-distance known-distance)
                           (and (= candidate-distance known-distance)
                                (or (null known-hop)
                                    (string< candidate-hop known-hop))))
                   (setf (gethash neighbor distance) candidate-distance
                         (gethash neighbor first-hop) candidate-hop))))
             neighbors)))))))

(defun wireguard-topology-object (mode adjacency nodes zone-gateways region-gateways)
  (let ((edges nil)
        (domains nil)
        (degraded nil))
    (maphash
     (lambda (left neighbors)
       (maphash (lambda (right edge)
                  (when (string< left right)
                    (push (list left right (first edge) (second edge)) edges)))
                neighbors))
     adjacency)
    (maphash
     (lambda (name node)
       (multiple-value-bind (region zone) (node-network-domain node)
         (push (list name region zone) domains)))
     nodes)
    (maphash (lambda (domain gateways)
               (when (< (length gateways) 2)
                 (push (list :zone (first domain) (second domain)) degraded)))
             zone-gateways)
    (maphash (lambda (region gateways)
               (when (< (length gateways) 2)
                 (push (list :region region) degraded)))
             region-gateways)
    (unless (eq mode :full-mesh)
      (maphash (lambda (name neighbors)
                 (when (> (hash-table-count neighbors) 6)
                   (push (list :peer-degree name (hash-table-count neighbors))
                         degraded)))
               adjacency))
    (list :mode mode
          :domains (sort domains #'string< :key #'first)
          :zone-gateways
          (sort (loop for key being the hash-keys of zone-gateways
                      collect (list key (sort (copy-list (gethash key zone-gateways)) #'string<)))
                #'string< :key (lambda (entry) (format nil "~{~A/~}" (first entry))))
          :region-gateways
          (sort (loop for key being the hash-keys of region-gateways
                      collect (list key (sort (copy-list (gethash key region-gateways)) #'string<)))
                #'string< :key #'first)
          :degraded-domains
          (sort degraded #'string< :key (lambda (entry) (format nil "~{~A/~}" entry)))
          :edges (sort edges #'string< :key (lambda (edge)
                                               (format nil "~A/~A" (first edge) (second edge)))))))

(defun plan-wireguard-topology
    (node-records &key (full-mesh-limit 8)
                        (transit-node-names nil transit-node-names-p))
  "Plan direct peers and deterministic next hops for NODE-RECORDS.
When TRANSIT-NODE-NAMES is supplied, other nodes remain reachable leaves but
cannot forward traffic between healthy nodes."
  (let ((nodes (make-hash-table :test #'equal))
        (adjacency (make-hash-table :test #'equal))
        (zones (make-hash-table :test #'equal))
        (regions (make-hash-table :test #'equal))
        (zone-gateways (make-hash-table :test #'equal))
        (region-gateways (make-hash-table :test #'equal))
        (transit-index (make-hash-table :test #'equal))
        (transit-nodes nil)
        (leaf-nodes nil))
    (dolist (node node-records)
      (setf (gethash (overlay-node-name node) nodes) node
            (gethash (overlay-node-name node) adjacency) (make-hash-table :test #'equal))
      (if (or (not transit-node-names-p)
              (member (overlay-node-name node) transit-node-names :test #'string=))
          (push node transit-nodes)
          (push node leaf-nodes)))
    ;; Only stable nodes form rings and may become a third party's next hop.
    (dolist (node transit-nodes)
      (setf (gethash (overlay-node-name node) transit-index) t)
      (multiple-value-bind (region zone) (node-network-domain node)
        (topology-group-push zones (list region zone) (overlay-node-name node))
        (topology-group-push regions region (overlay-node-name node))))
    (let ((mode (if (<= (length node-records) full-mesh-limit) :full-mesh :sparse)))
      (if (eq mode :full-mesh)
          (let ((names (sort (mapcar #'overlay-node-name (copy-list node-records)) #'string<)))
            (loop for tail on names
                  do (dolist (right (rest tail))
                       (wireguard-topology-add-edge adjacency (first tail) right 1 :direct))))
          (progn
            (maphash
             (lambda (domain names)
               (let ((ordered (sort (copy-list names) #'string<)))
                 (wireguard-topology-add-ring adjacency ordered 1 :zone)
                 (setf (gethash domain zone-gateways) (subseq ordered 0 (min 2 (length ordered))))))
             zones)
            (maphash
             (lambda (region names)
               (declare (ignore names))
               (let ((domains
                       (sort (loop for domain being the hash-keys of zone-gateways
                                   when (string= region (first domain)) collect domain)
                             #'string< :key #'second)))
                 (dotimes (index 2)
                   (wireguard-topology-add-ring
                    adjacency
                    (loop for domain in domains
                          for gateways = (gethash domain zone-gateways)
                          when (< index (length gateways)) collect (nth index gateways))
                    10 :zone-gateway))
                 (let ((candidates
                         (sort (remove-duplicates
                                (loop for domain in domains append
                                      (copy-list (gethash domain zone-gateways)))
                                :test #'string=)
                               #'string<)))
                   (setf (gethash region region-gateways)
                         (subseq candidates 0 (min 2 (length candidates)))))))
             regions)
            (dotimes (index 2)
              (wireguard-topology-add-ring
               adjacency
               (sort (loop for region being the hash-keys of region-gateways
                           for gateways = (gethash region region-gateways)
                           when (< index (length gateways)) collect (nth index gateways))
                     #'string<)
               100 :region-gateway))
            ;; Recovering nodes attach to up to two stable nodes in the closest
            ;; failure domain. They are destinations, never transit shortcuts.
            (let ((ordered-leaves
                    (sort (copy-list leaf-nodes) #'string< :key #'overlay-node-name)))
              (dolist (leaf ordered-leaves)
              (multiple-value-bind (leaf-region leaf-zone) (node-network-domain leaf)
                (let* ((same-zone
                         (remove-if-not
                          (lambda (candidate)
                            (multiple-value-bind (region zone)
                                (node-network-domain candidate)
                              (and (string= region leaf-region)
                                   (string= zone leaf-zone))))
                          transit-nodes))
                       (same-region
                         (remove-if-not
                          (lambda (candidate)
                            (multiple-value-bind (region zone)
                                (node-network-domain candidate)
                              (declare (ignore zone))
                              (string= region leaf-region)))
                          transit-nodes))
                       (candidates
                         (sort (copy-list (or same-zone same-region transit-nodes))
                               #'string< :key #'overlay-node-name))
                       (selected
                         (subseq
                          (sort (copy-list candidates)
                                (lambda (left right)
                                  (let ((left-degree
                                          (hash-table-count
                                           (gethash (overlay-node-name left) adjacency)))
                                        (right-degree
                                          (hash-table-count
                                           (gethash (overlay-node-name right) adjacency))))
                                    (or (< left-degree right-degree)
                                        (and (= left-degree right-degree)
                                             (string< (overlay-node-name left)
                                                      (overlay-node-name right)))))))
                          0 (min 2 (length candidates)))))
                  (dolist (gateway selected)
                    (wireguard-topology-add-edge
                     adjacency (overlay-node-name leaf) (overlay-node-name gateway)
                     1 :recovering-leaf))))))
            ;; Immediately after a control-plane restart every ready node may
            ;; still be inside its conservative stability window. Direct edges
            ;; preserve reachability without appointing any of them as transit.
            (when (null transit-nodes)
              (setf mode :recovery-full-mesh)
              (let ((names (sort (mapcar #'overlay-node-name
                                         (copy-list node-records))
                                 #'string<)))
                (loop for tail on names
                      do (dolist (right (rest tail))
                           (wireguard-topology-add-edge
                            adjacency (first tail) right 1 :recovery-direct)))))))
      (make-wireguard-topology-plan
       :mode mode :adjacency adjacency :nodes nodes :transit-nodes transit-index
       :object (wireguard-topology-object
                mode adjacency nodes zone-gateways region-gateways)))))

