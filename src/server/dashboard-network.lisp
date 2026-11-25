;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The Network tab of `gr8s dashboard' (podster-5hv): a service graph of the cluster's
;;;; workloads drawn from its flow events. The backend folds each flow into an edge
;;;; between two workloads -- a Pod resolved through its owners to its Deployment,
;;;; StatefulSet, DaemonSet or Job, a Service, a Node, the LAN or the world -- and keeps
;;;; each edge's counts over the last 15 minutes and its latest flows. The page
;;;; (dashboard-network.html, Cytoscape.js with the fcose and dagre layouts) polls the
;;;; graph and asks for an edge's flows when one is picked.
;;;;
;;;; A connection between two Pods is seen twice, leaving its source and arriving at its
;;;; destination; only the source's sighting counts, unless the destination dropped it.

(in-package #:gr8s.server)

(defparameter +dashboard-network-html+ #.(dashboard-agent-asset-text "dashboard-network.html"))

(defparameter +dashboard-network-assets+
  (list (list "cytoscape.js" #.(dashboard-agent-asset-text "assets/graph/cytoscape.js"))
        (list "layout-base.js" #.(dashboard-agent-asset-text "assets/graph/layout-base.js"))
        (list "cose-base.js" #.(dashboard-agent-asset-text "assets/graph/cose-base.js"))
        (list "cytoscape-fcose.js" #.(dashboard-agent-asset-text "assets/graph/cytoscape-fcose.js"))
        (list "dagre.js" #.(dashboard-agent-asset-text "assets/graph/dagre.js"))
        (list "cytoscape-dagre.js" #.(dashboard-agent-asset-text "assets/graph/cytoscape-dagre.js")))
  "The graph's scripts, (name text), each NIL when `make graph-assets' has not run.")

(defparameter +network-window-seconds+ (* 15 60)
  "How far back the graph counts: an edge unseen for longer leaves it.")

(defparameter +network-bucket-seconds+ 10
  "The resolution of an edge's counts.")

(defparameter +network-recent-flows+ 40
  "How many of an edge's latest flows it keeps to show.")

(defparameter +network-latest-flows+ 300
  "How many of the cluster's latest flows the flow table keeps.")

(defparameter +network-image-icons+
  '(("postgres" "postgresql" "PostgreSQL") ("mariadb" "mariadb" "MariaDB") ("mysql" "mysql" "MySQL")
    ("valkey" "redis" "Valkey") ("redis" "redis" "Redis") ("mongo" "mongodb" "MongoDB")
    ("kafka" "apachekafka" "Kafka") ("rabbitmq" "rabbitmq" "RabbitMQ")
    ("elasticsearch" "elasticsearch" "Elasticsearch") ("opensearch" "opensearch" "OpenSearch")
    ("grafana" "grafana" "Grafana") ("loki" "grafana" "Loki")
    ("node-exporter" "prometheus" "node exporter") ("alertmanager" "prometheus" "Alertmanager")
    ("kube-state-metrics" "prometheus" "kube-state-metrics") ("prometheus" "prometheus" "Prometheus")
    ("nginx" "nginx" "nginx") ("envoy" "envoyproxy" "Envoy") ("openbao" "openbao" "OpenBao")
    ("vault" "vault" "Vault") ("minio" "minio" "MinIO") ("etcd" "etcd" "etcd")
    ("zot" "lucide-archive" "zot registry") ("registry" "lucide-archive" "registry")
    ("rustfs" "lucide-hard-drive" "RustFS") ("memcached" "lucide-database" "memcached")
    ("coredns" "lucide-network" "CoreDNS"))
  "Fragments of a workload's image or name, the icon to draw it with and the software it is.")

(defparameter +network-kind-icons+
  '(("Deployment" . "lucide-layers") ("ReplicaSet" . "lucide-layers") ("StatefulSet" . "lucide-database")
    ("DaemonSet" . "lucide-boxes") ("Job" . "lucide-timer") ("CronJob" . "lucide-timer") ("Pod" . "lucide-box")
    ("Service" . "lucide-split") ("Gateway" . "lucide-door-open") ("Clients" . "lucide-users") ("Node" . "lucide-server") ("LAN" . "lucide-network")
    ("External" . "lucide-router") ("World" . "lucide-globe"))
  "The icon for a node whose software isn't recognised, by its kind.")

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun network-asset-files (directory binary)
    "(name content) for each file under assets/graph/DIRECTORY/, read when this file is
compiled: octets when BINARY, else text. NIL when `make graph-assets' has not run."
    (let ((root (merge-pathnames (format nil "../../assets/graph/~A/" directory)
                                 (or *compile-file-truename* *load-truename*))))
      (loop for path in (directory (merge-pathnames "*.*" root))
            collect (list (file-namestring path)
                          (if binary
                              (with-open-file (in path :element-type '(unsigned-byte 8))
                                (let ((octets (make-array (file-length in) :element-type '(unsigned-byte 8))))
                                  (read-sequence octets in)
                                  octets))
                              (uiop:read-file-string path)))))))

(defparameter +network-icon-files+ '#.(network-asset-files "icons" nil)
  "The Network tab's icons, (file svg-text).")

(defparameter +network-font-files+ '#.(network-asset-files "fonts" t)
  "The Network tab's font files, (file octets).")

;;; The cluster's shape, refreshed from the API, which flows are resolved against

(defstruct (network-topology (:constructor make-network-topology ()))
  ;; (namespace . pod) -> workload, (namespace kind name)
  (pods (make-hash-table :test #'equal))
  ;; Pod IP -> workload
  (addresses (make-hash-table :test #'equal))
  ;; workload -> its first Pod's container images, space-separated
  (images (make-hash-table :test #'equal))
  ;; ClusterIP -> (namespace "Service" name)
  (services (make-hash-table :test #'equal))
  ;; Node InternalIP, and its podCIDR's gateway address -> node name
  (nodes (make-hash-table :test #'equal))
  ;; workload -> its web endpoints, (namespace service port https-p), best first
  (web (make-hash-table :test #'equal))
  ;; "namespace/name" of a route -> the Gateway it hangs from, (namespace "Gateway" name)
  (routes (make-hash-table :test #'equal))
  ;; (workload . target port) a route sends to -> the Gateway that sends it there
  (gateway-backends (make-hash-table :test #'equal)))

(defparameter +network-web-ports+ '(80 8080 3000 8000 9090 443 8443)
  "Port numbers a web UI usually answers on.")

(defun network-service-web-ports (service)
  "SERVICE's ports that look like a web UI's, as (port https-p), best first: by name or
appProtocol, else by number."
  (let ((ports nil))
    (loop for port across (gethash "ports" (gethash "spec" service) #())
          for number = (gethash "port" port)
          for name = (string-downcase (gethash "name" port ""))
          for app = (string-downcase (gethash "appProtocol" port ""))
          for https = (or (search "https" name) (search "https" app) (member number '(443 8443)))
          for score = (cond ((or (search "http" name) (search "http" app) (member name '("web" "ui") :test #'equal)) 2)
                            ((member number +network-web-ports+) 1)
                            (t 0))
          when (and (integerp number) (plusp score))
            do (push (list score number (and https t)) ports))
    (mapcar #'rest (stable-sort (nreverse ports) #'> :key #'first))))

(defun network-selector-matches-p (selector labels)
  "Whether every SELECTOR label is among LABELS (a Service's selector, a Pod's labels)."
  (and (hash-table-p selector) (plusp (hash-table-count selector)) (hash-table-p labels)
       (loop for key being the hash-keys of selector using (hash-value value)
             always (equal value (gethash key labels)))))

(defun network-pod-workload (pod replicasets)
  "POD's workload, (namespace kind name): the controller that owns it, through its
ReplicaSet to a Deployment; the Pod itself when nothing does. REPLICASETS maps
(namespace . name) to a ReplicaSet object."
  (let* ((metadata (gethash "metadata" pod))
         (namespace (gethash "namespace" metadata))
         (owner (let ((owners (gethash "ownerReferences" metadata)))
                  (and (plusp (length owners)) (aref owners 0)))))
    (cond ((null owner) (list namespace "Pod" (gethash "name" metadata)))
          ((equal (gethash "kind" owner) "ReplicaSet")
           (let* ((replicaset (gethash (cons namespace (gethash "name" owner)) replicasets))
                  (owners (and replicaset (gethash "ownerReferences" (gethash "metadata" replicaset)))))
             (if (plusp (length owners))
                 (list namespace (gethash "kind" (aref owners 0)) (gethash "name" (aref owners 0)))
                 (list namespace "ReplicaSet" (gethash "name" owner)))))
          (t (list namespace (gethash "kind" owner) (gethash "name" owner))))))

(defun network-pod-cidr-gateway (cidr)
  "The first address of an IPv4 CIDR, where a node's Pods see it, or NIL."
  (let ((slash (position #\/ cidr)))
    (when slash
      (let ((octets (mapcar #'parse-integer (uiop:split-string (subseq cidr 0 slash) :separator "."))))
        (when (= 4 (length octets))
          (format nil "~{~D~^.~}" octets))))))

(defun network-route-gateway (route)
  "The Gateway a Gateway API ROUTE hangs from, (namespace \"Gateway\" name), or NIL."
  (let* ((namespace (gethash "namespace" (gethash "metadata" route)))
         (parent (find-if (lambda (ref) (member (gethash "kind" ref "Gateway") '("Gateway") :test #'equal))
                          (coerce (gethash "parentRefs" (gethash "spec" route) #()) 'list))))
    (and parent (list (gethash "namespace" parent namespace) "Gateway" (gethash "name" parent)))))

(defun network-service-target-port (service port)
  "The target port SERVICE sends its PORT to: a number, or NIL when it is a name."
  (let ((entry (find port (coerce (gethash "ports" (gethash "spec" service) #()) 'list)
                     :key (lambda (entry) (gethash "port" entry)))))
    (and entry (let ((target (gethash "targetPort" entry port))) (and (integerp target) target)))))

(defun build-network-topology (pods replicasets services nodes &optional routes)
  "A NETWORK-TOPOLOGY from lists of Pod, ReplicaSet, Service and Node objects, and the
Gateway API's routes."
  (let ((topology (make-network-topology))
        (by-name (make-hash-table :test #'equal)))
    (dolist (replicaset replicasets)
      (let ((metadata (gethash "metadata" replicaset)))
        (setf (gethash (cons (gethash "namespace" metadata) (gethash "name" metadata)) by-name) replicaset)))
    (dolist (pod pods)
      (let ((workload (network-pod-workload pod by-name))
            (metadata (gethash "metadata" pod))
            (status (gethash "status" pod)))
        (setf (gethash (cons (gethash "namespace" metadata) (gethash "name" metadata))
                       (network-topology-pods topology))
              workload)
        (let ((address (and status (gethash "podIP" status))))
          ;; A host-network Pod shares its node's address, which stays the node's.
          (when (and (plusp (length address))
                     (not (eq t (gethash "hostNetwork" (gethash "spec" pod)))))
            (setf (gethash address (network-topology-addresses topology)) workload)))
        (unless (gethash workload (network-topology-images topology))
          (setf (gethash workload (network-topology-images topology))
                (format nil "~{~A~^ ~}"
                        (map 'list (lambda (container) (gethash "image" container ""))
                             (gethash "containers" (gethash "spec" pod) #())))))))
    (dolist (service services)
      (let ((ports (network-service-web-ports service))
            (namespace (gethash "namespace" (gethash "metadata" service)))
            (selector (gethash "selector" (gethash "spec" service))))
        (when ports
          (dolist (pod pods)
            (when (and (equal namespace (gethash "namespace" (gethash "metadata" pod)))
                       (network-selector-matches-p selector (gethash "labels" (gethash "metadata" pod))))
              (let ((workload (gethash (cons namespace (gethash "name" (gethash "metadata" pod)))
                                       (network-topology-pods topology))))
                (dolist (port ports)
                  (pushnew (list namespace (gethash "name" (gethash "metadata" service)) (first port) (second port))
                           (gethash workload (network-topology-web topology)) :test #'equal)))))))
      (let ((address (gethash "clusterIP" (gethash "spec" service)))
            (metadata (gethash "metadata" service)))
        (when (and (plusp (length address)) (not (equal address "None")))
          (setf (gethash address (network-topology-services topology))
                (list (gethash "namespace" metadata) "Service" (gethash "name" metadata))))))
    (maphash (lambda (workload endpoints) (setf (gethash workload (network-topology-web topology)) (reverse endpoints)))
             (network-topology-web topology))
    ;; What a Gateway sends where: each route's backend Services, to the workloads behind them.
    (let ((by-service (make-hash-table :test #'equal)))
      (dolist (service services)
        (let ((metadata (gethash "metadata" service)))
          (setf (gethash (cons (gethash "namespace" metadata) (gethash "name" metadata)) by-service) service)))
      (dolist (route routes)
        (let ((gateway (network-route-gateway route))
              (namespace (gethash "namespace" (gethash "metadata" route))))
          (when gateway
            (setf (gethash (format nil "~A/~A" namespace (gethash "name" (gethash "metadata" route)))
                           (network-topology-routes topology))
                  gateway)
            (loop for rule across (gethash "rules" (gethash "spec" route) #())
                  do (loop for ref across (gethash "backendRefs" rule #())
                           for service = (gethash (cons (gethash "namespace" ref namespace) (gethash "name" ref)) by-service)
                           for target = (and service (network-service-target-port service (gethash "port" ref)))
                           when target
                             do (dolist (pod pods)
                                  (when (and (equal (gethash "namespace" (gethash "metadata" service))
                                                    (gethash "namespace" (gethash "metadata" pod)))
                                             (network-selector-matches-p (gethash "selector" (gethash "spec" service))
                                                                         (gethash "labels" (gethash "metadata" pod))))
                                    (let ((workload (gethash (cons (gethash "namespace" (gethash "metadata" pod))
                                                                   (gethash "name" (gethash "metadata" pod)))
                                                             (network-topology-pods topology))))
                                      (setf (gethash (cons workload target) (network-topology-gateway-backends topology))
                                            gateway))))))))))
    (dolist (node nodes)
      (let ((name (gethash "name" (gethash "metadata" node)))
            (cidr (gethash "podCIDR" (gethash "spec" node) "")))
        (loop for address across (gethash "addresses" (gethash "status" node) #())
              when (equal (gethash "type" address) "InternalIP")
                do (setf (gethash (gethash "address" address) (network-topology-nodes topology)) name))
        (let ((gateway (and (plusp (length cidr)) (network-pod-cidr-gateway cidr))))
          (when gateway (setf (gethash gateway (network-topology-nodes topology)) name)))))
    topology))

(defun network-address-class (address)
  "How an address that isn't a Pod's, a Service's or a node's should be drawn:
:lan (link-local, unspecified), :private or :world."
  (cond ((or (uiop:string-prefix-p "fe80:" (string-downcase address))
             (uiop:string-prefix-p "169.254." address)
             (member address '("::" "0.0.0.0" "0:0:0:0:0:0:0:0") :test #'equal))
         :lan)
        ((or (uiop:string-prefix-p "10." address) (uiop:string-prefix-p "192.168." address)
             (and (uiop:string-prefix-p "172." address)
                  (let ((second (ignore-errors (parse-integer address :start 4 :junk-allowed t))))
                    (and second (<= 16 second 31))))
             (uiop:string-prefix-p "fd" (string-downcase address))
             (uiop:string-prefix-p "fc" (string-downcase address)))
         :private)
        (t :world)))

(defun network-peer-workload (topology flow)
  "The workload at the far end of FLOW: the Pod the flow names, else whatever owns its address."
  (let ((pod (gethash "peerPod" flow))
        (namespace (gethash "peerNamespace" flow))
        (address (gethash "peerAddress" flow "")))
    (or (and pod namespace
             (or (gethash (cons namespace pod) (network-topology-pods topology))
                 (list namespace "Pod" pod)))
        (gethash address (network-topology-addresses topology))
        (gethash address (network-topology-services topology))
        (let ((node (gethash address (network-topology-nodes topology))))
          (and node (list nil "Node" node)))
        (ecase (network-address-class address)
          (:lan (list nil "LAN" "link-local"))
          (:private (list nil "External" address))
          (:world (list nil "World" "world"))))))

(defun network-gateway-client (topology flow)
  "Who made the request a Gateway's record FLOW describes, as the graph draws it: the world
for a public address, else the LAN's clients -- a node's address included, as a person
browsing from a cluster machine is a client to the Gateway, not that node's software."
  (declare (ignore topology))
  (if (eq :world (network-address-class (gethash "peerAddress" flow "")))
      (list nil "World" "world")
      (list nil "Clients" "LAN clients")))

(defun network-workload-id (workload)
  "A workload's node id: namespace/kind/name, or kind/name outside a namespace."
  (format nil "~{~A~^/~}" (remove nil workload)))

(defun network-image-name (reference)
  "An image REFERENCE's repository name: registry.example:5000/team/postgres:17 is postgres."
  (let* ((reference (string-downcase reference))
         (at (position #\@ reference))
         (reference (if at (subseq reference 0 at) reference))
         (slash (position #\/ reference :from-end t))
         (name (subseq reference (if slash (1+ slash) 0)))
         (colon (position #\: name)))
    (if colon (subseq name 0 colon) name)))

(defun network-workload-software (topology workload)
  "(values icon software) for WORKLOAD: the software its images' names (never the registry
they come from), or else its own name, show it to be, with that software's icon; failing
both, its kind's icon and NIL."
  (let* ((names (cons (string-downcase (third workload))
                      (mapcar #'network-image-name
                              (remove "" (uiop:split-string (gethash workload (network-topology-images topology) "")
                                                            :separator " ")
                                      :test #'equal))))
         (match (find-if (lambda (entry) (some (lambda (name) (search (first entry) name)) names))
                         +network-image-icons+)))
    (if match
        (values (second match) (third match))
        (values (or (cdr (assoc (second workload) +network-kind-icons+ :test #'equal)) "lucide-box") nil))))

;;; The graph: edges between workloads, with their counts and latest flows

(defstruct (network-edge (:constructor make-network-edge (source target)))
  source target
  ;; bucket (universal time / +network-bucket-seconds+) -> #(flows dropped errors bytes)
  (buckets (make-hash-table))
  ;; "port/PROTOCOL" -> flows, for the edge's label
  (ports (make-hash-table :test #'equal))
  (recent nil)
  (last-seen 0)
  ;; HTTP latency samples (ns) in the window, for a median
  (latencies nil))

(defun network-edge-id (edge)
  (format nil "~A>~A" (network-edge-source edge) (network-edge-target edge)))

(defstruct (network-graph (:constructor make-network-graph ()))
  (lock (bt:make-lock "gr8s network graph"))
  (topology (make-network-topology))
  ;; (source-id . target-id) -> network-edge
  (edges (make-hash-table :test #'equal))
  ;; node id -> (workload icon software)
  (nodes (make-hash-table :test #'equal))
  ;; The latest flows counted, newest first, each (edge-id . flow), and how many
  (latest nil) (latest-count 0))

(defun network-flow-time (flow)
  "FLOW's universal time, or now."
  (or (gr8s.kube-client::parse-rfc3339 (gethash "time" flow "")) (get-universal-time)))

(defun network-flow-endpoints (topology flow)
  "(values source target port counted-p) of FLOW's connection. A Gateway's request record
is the client's connection to the Gateway. A connection from a node's own address to a port
a Gateway route sends to is the Gateway's, which runs on every node. A forwarded connection
arriving at a Pod from another known Pod isn't counted: its source counted it leaving."
  (let* ((l7 (gethash "l7" flow))
         (route (and (hash-table-p l7) (gethash "route" l7)))
         (gateway (and route (gethash route (network-topology-routes topology)))))
    (when gateway
      (return-from network-flow-endpoints
        (values (network-gateway-client topology flow) gateway (gethash "listenerPort" l7) t))))
  (unless (gethash "pod" flow)
    ;; A request record whose route isn't known yet, and that names no Pod.
    (return-from network-flow-endpoints (values nil nil nil nil)))
  (let* ((namespace (gethash "namespace" flow))
         (pod (gethash "pod" flow))
         (here (or (gethash (cons namespace pod) (network-topology-pods topology))
                   (list namespace "Pod" pod)))
         (egress (equal (gethash "direction" flow) "egress"))
         (there (let ((peer (network-peer-workload topology flow)))
                  (or (and (not egress) (equal (second peer) "Node")
                           (gethash (cons here (gethash "podPort" flow)) (network-topology-gateway-backends topology)))
                      peer)))
         (port (if egress (gethash "peerPort" flow) (gethash "podPort" flow)))
         (counted (or egress
                      (equal (gethash "verdict" flow) "DROPPED")
                      (not (first there))   ; from outside the cluster's namespaces
                      (member (second there) '("Service" "Gateway") :test #'equal))))
    (if egress
        (values here there port counted)
        (values there here port counted))))

(defun network-graph-note-flow (graph flow)
  "Fold FLOW, a flow event object, into GRAPH."
  (when (or (gethash "pod" flow) (hash-table-p (gethash "l7" flow)))
    (bt:with-lock-held ((network-graph-lock graph))
      (let ((topology (network-graph-topology graph)))
        (multiple-value-bind (source target port counted) (network-flow-endpoints topology flow)
          (when counted
            (let* ((source-id (network-workload-id source))
                   (target-id (network-workload-id target))
                   (edge (or (gethash (cons source-id target-id) (network-graph-edges graph))
                             (setf (gethash (cons source-id target-id) (network-graph-edges graph))
                                   (make-network-edge source-id target-id))))
                   (time (network-flow-time flow))
                   (bucket (or (gethash (floor time +network-bucket-seconds+) (network-edge-buckets edge))
                               (setf (gethash (floor time +network-bucket-seconds+) (network-edge-buckets edge))
                                     (vector 0 0 0 0))))
                   (dropped (equal (gethash "verdict" flow) "DROPPED"))
                   (l7 (gethash "l7" flow))
                   (code (and (hash-table-p l7) (gethash "code" l7 0))))
              (dolist (workload (list source target))
                (let ((id (network-workload-id workload)))
                  (unless (gethash id (network-graph-nodes graph))
                    (setf (gethash id (network-graph-nodes graph))
                          (cons workload (multiple-value-list (network-workload-software topology workload)))))))
              (incf (aref bucket 0))
              (when dropped (incf (aref bucket 1)))
              (when (and code (>= code 500)) (incf (aref bucket 2)))
              (incf (aref bucket 3) (gethash "length" flow 0))
              (when (and (hash-table-p l7) (plusp (gethash "latencyNs" l7 0)))
                (push (cons time (gethash "latencyNs" l7)) (network-edge-latencies edge)))
              (let ((key (format nil "~@[~A/~]~A" port (gethash "protocol" flow ""))))
                (when (plusp (length key)) (incf (gethash key (network-edge-ports edge) 0))))
              (setf (network-edge-last-seen edge) (max time (network-edge-last-seen edge)))
              (push flow (network-edge-recent edge))
              (push (cons (network-edge-id edge) flow) (network-graph-latest graph))
              (when (> (incf (network-graph-latest-count graph)) (* 2 +network-latest-flows+))
                (setf (network-graph-latest graph) (subseq (network-graph-latest graph) 0 +network-latest-flows+)
                      (network-graph-latest-count graph) +network-latest-flows+))
              (when (> (length (network-edge-recent edge)) +network-recent-flows+)
                (setf (network-edge-recent edge)
                      (subseq (network-edge-recent edge) 0 +network-recent-flows+))))))))))

(defun network-edge-window (edge now seconds)
  "EDGE's (flows dropped errors bytes) over the last SECONDS before NOW."
  (let ((totals (vector 0 0 0 0))
        (from (floor (- now seconds) +network-bucket-seconds+)))
    (maphash (lambda (bucket counts)
               (when (>= bucket from)
                 (dotimes (i 4) (incf (aref totals i) (aref counts i)))))
             (network-edge-buckets edge))
    totals))

(defun network-graph-expire (graph now)
  "Forget what GRAPH saw before its window: old counts, then edges and nodes nothing uses."
  (bt:with-lock-held ((network-graph-lock graph))
    (let ((oldest (floor (- now +network-window-seconds+) +network-bucket-seconds+))
          (used (make-hash-table :test #'equal)))
      (maphash (lambda (key edge)
                 (if (< (network-edge-last-seen edge) (- now +network-window-seconds+))
                     (remhash key (network-graph-edges graph))
                     (progn
                       (maphash (lambda (bucket counts)
                                  (declare (ignore counts))
                                  (when (< bucket oldest) (remhash bucket (network-edge-buckets edge))))
                                (network-edge-buckets edge))
                       (setf (network-edge-latencies edge)
                             (remove-if (lambda (sample) (< (car sample) (- now +network-window-seconds+)))
                                        (network-edge-latencies edge)))
                       (setf (gethash (network-edge-source edge) used) t
                             (gethash (network-edge-target edge) used) t))))
               (network-graph-edges graph))
      (maphash (lambda (id node) (declare (ignore node)) (unless (gethash id used) (remhash id (network-graph-nodes graph))))
               (network-graph-nodes graph)))))

(defun network-edge-ports-summary (edge)
  "EDGE's ports, busiest first: at most three, then +N."
  (let ((ports (sort (loop for port being the hash-keys of (network-edge-ports edge) using (hash-value count)
                           collect (cons port count))
                     #'> :key #'cdr)))
    (coerce (append (mapcar #'car (subseq ports 0 (min 3 (length ports))))
                    (when (> (length ports) 3) (list (format nil "+~D" (- (length ports) 3)))))
            'vector)))

(defun network-graph-object (graph &optional (now (get-universal-time)) (favicon-p (constantly nil)))
  "GRAPH as the page draws it: its nodes, and its edges with their counts over the last
1, 5 and 15 minutes."
  (bt:with-lock-held ((network-graph-lock graph))
    (flet ((window (edge seconds)
             (let ((totals (network-edge-window edge now seconds)))
               (gr8s-diagnose::object "flows" (aref totals 0) "dropped" (aref totals 1)
                                      "errors" (aref totals 2) "bytes" (aref totals 3)))))
      (gr8s-diagnose::object
       "nodes" (coerce (loop for id being the hash-keys of (network-graph-nodes graph) using (hash-value node)
                             collect (destructuring-bind (workload icon software) node
                                       (gr8s-diagnose::object "id" id "namespace" (or (first workload) 'null)
                                                              "kind" (second workload) "name" (third workload)
                                                              "icon" icon "software" (or software 'null)
                                                              "favicon" (and (funcall favicon-p id) t))))
                       'vector)
       "edges" (coerce (loop for edge being the hash-values of (network-graph-edges graph)
                             collect (let ((latencies (sort (mapcar #'cdr (network-edge-latencies edge)) #'<)))
                                       (gr8s-diagnose::object
                                        "id" (network-edge-id edge)
                                        "source" (network-edge-source edge) "target" (network-edge-target edge)
                                        "ports" (network-edge-ports-summary edge)
                                        "lastSeen" (- (network-edge-last-seen edge) 2208988800)
                                        "m1" (window edge 60) "m5" (window edge 300) "m15" (window edge 900)
                                        "latencyMs" (if latencies
                                                        (round (nth (floor (length latencies) 2) latencies) 1000000)
                                                        'null))))
                       'vector)))))

(defun network-graph-latest-flows (graph)
  "The cluster's latest counted flows, newest first, each with its edge's id as \"edge\"."
  (bt:with-lock-held ((network-graph-lock graph))
    (loop for (edge . flow) in (network-graph-latest graph)
          repeat +network-latest-flows+
          collect (let ((copy (alexandria:copy-hash-table flow)))
                    (setf (gethash "edge" copy) edge)
                    copy))))

(defun network-graph-edge-flows (graph id)
  "The latest flows of the edge named ID, newest first, each with ID as \"edge\"; or NIL."
  (bt:with-lock-held ((network-graph-lock graph))
    (loop for edge being the hash-values of (network-graph-edges graph)
          when (equal id (network-edge-id edge))
            return (mapcar (lambda (flow)
                             (let ((copy (alexandria:copy-hash-table flow)))
                               (setf (gethash "edge" copy) id)
                               copy))
                           (network-edge-recent edge)))))

;;; Favicons: a workload's own icon, read from its web UI through the API's Service proxy

(defparameter +network-favicon-limit+ (* 64 1024) "The largest favicon accepted.")
(defparameter +network-page-limit+ (* 256 1024) "The most of a web UI's page read to find its icon link.")
(defparameter +network-favicon-retry-seconds+ 3600 "How long a favicon, or the lack of one, is remembered.")

(defun network-image-type (octets)
  "The content type of OCTETS when they are an image a page may show, by their magic bytes
or, for SVG, their opening tag; NIL otherwise. An SVG can carry script, which a page's
<img> never runs; the favicon endpoint also serves every icon sandboxed, so opening one
directly runs nothing either."
  (flet ((starts (&rest bytes) (and (>= (length octets) (length bytes))
                                    (every (lambda (byte index) (= byte (aref octets index)))
                                           bytes (alexandria:iota (length bytes))))))
    (cond ((starts #x89 #x50 #x4e #x47) "image/png")
          ((starts #x00 #x00 #x01 #x00) "image/x-icon")
          ((starts #x47 #x49 #x46 #x38) "image/gif")
          ((starts #xff #xd8 #xff) "image/jpeg")
          ((and (starts #x52 #x49 #x46 #x46) (>= (length octets) 12)
                (equalp (subseq octets 8 12) #(#x57 #x45 #x42 #x50)))
           "image/webp")
          ((let* ((head (ignore-errors (trivial-utf-8:utf-8-bytes-to-string
                                        (subseq octets 0 (min 512 (length octets))))))
                  (text (and head (string-left-trim '(#\Space #\Tab #\Newline #\Return #\Page) head))))
             (and text (or (uiop:string-prefix-p "<svg" text)
                           (and (uiop:string-prefix-p "<?xml" text) (search "<svg" text)))))
           "image/svg+xml"))))

(defun network-page-icon-links (html)
  "The icon links in HTML's <link> tags, in page order: each href of a rel naming icon."
  (let ((links nil))
    (cl-ppcre:do-matches-as-strings (tag "(?is)<link\\b[^>]*>" html)
      (let ((rel (cl-ppcre:register-groups-bind (value) ("(?is)\\brel\\s*=\\s*[\"']?([^\"'>]*)" tag) value))
            (href (cl-ppcre:register-groups-bind (value) ("(?is)\\bhref\\s*=\\s*[\"']?([^\"' >]*)" tag) value)))
        (when (and rel href (search "icon" (string-downcase rel)))
          (push href links))))
    (nreverse links)))

(defun network-proxy-target (base page href)
  "The Service-proxy path for HREF, a link on PAGE (a path under the proxy BASE), or NIL for
one that leaves the app."
  (cond ((or (search "://" href) (uiop:string-prefix-p "//" href)) nil)
        ((uiop:string-prefix-p "/api/v1/namespaces/" href) href)
        ((uiop:string-prefix-p "/" href) (concatenate 'string base href))
        (t (concatenate 'string base (subseq page 0 (1+ (or (position #\/ page :from-end t) 0))) href))))

(defun network-url-path (url)
  "URL's path when it is absolute (scheme://host/path), else URL itself."
  (let ((scheme (search "://" url)))
    (if scheme
        (let ((slash (position #\/ url :start (+ scheme 3))))
          (if slash (subseq url slash) "/"))
        url)))

(defun network-data-uri-octets (href)
  "The octets of a base64 data: URI, or NIL."
  (let ((comma (position #\, href)))
    (when (and comma (uiop:string-prefix-p "data:" href) (search ";base64" (subseq href 0 comma)))
      (ignore-errors (coerce (ag-grpc:base64-decode (subseq href (1+ comma))) '(simple-array (unsigned-byte 8) (*)))))))

(defun fetch-network-favicon (config endpoint)
  "(values octets content-type) of the favicon ENDPOINT's web UI shows -- its page's icon
link, else /favicon.ico -- read through the API's Service proxy; NIL when it has none we
may show. ENDPOINT is (namespace service port https-p)."
  (destructuring-bind (namespace service port https) endpoint
    (let ((base (format nil "/api/v1/namespaces/~A/services/~:[~;https:~]~A:~D/proxy" namespace https service port)))
      (labels ((fetch (target limit) (ignore-errors (doctor-api-get config target :limit limit :seconds 5)))
               (image (target)
                 (multiple-value-bind (body status) (fetch target +network-favicon-limit+)
                   (let ((type (and (eql status 200) body (network-image-type body))))
                     (and type (values body type)))))
               (page (path redirects)
                 ;; The app's page, after up to REDIRECTS redirects within it; (values html path).
                 (multiple-value-bind (body status headers) (fetch (concatenate 'string base path) +network-page-limit+)
                   (cond ((and (member status '(301 302 303 307 308)) (plusp redirects))
                          (let* ((location (cdr (assoc :location headers)))
                                 ;; A redirect may name the API server absolutely; its path is what
                                 ;; matters, as every request goes to the API server anyway.
                                 (location (and location (network-url-path location)))
                                 (target (and location (network-proxy-target base path location))))
                            (when (and target (uiop:string-prefix-p base target))
                              (page (subseq target (length base)) (1- redirects)))))
                         ((and (eql status 200) body)
                          (values (ignore-errors (trivial-utf-8:utf-8-bytes-to-string body)) path))))))
        (multiple-value-bind (html path) (page "/" 2)
          (dolist (href (and html (network-page-icon-links html)))
            (let ((inline (network-data-uri-octets href)))
              (if inline
                  (let ((type (network-image-type inline)))
                    (when (and type (<= (length inline) +network-favicon-limit+))
                      (return-from fetch-network-favicon (values inline type))))
                  (let ((target (network-proxy-target base (or path "/") href)))
                    (when target
                      (multiple-value-bind (octets type) (image target)
                        (when type (return-from fetch-network-favicon (values octets type))))))))))
        (image (concatenate 'string base "/favicon.ico"))))))

;;; The tab: a graph fed from the cluster while its page is open

(defstruct (dashboard-network (:constructor make-dashboard-network (config)))
  config
  (graph (make-network-graph))
  ;; node id -> (universal-time octets content-type), octets NIL when it has none. Its own
  ;; lock, taken with no other held, so drawing the graph can ask it under the graph's.
  (favicons (make-hash-table :test #'equal))
  (favicons-lock (bt:make-lock "gr8s network favicons"))
  (lock (bt:make-lock "gr8s dashboard network"))
  started stopping flows-closer threads)

(defun dashboard-network-items (config resource)
  (coerce (gethash "items" (or (ignore-errors (debug-api-get-json config resource)) (make-hash-table)) #()) 'list))

(defun refresh-dashboard-network-topology (network)
  "Re-read the cluster's Pods, ReplicaSets, Services and Nodes."
  (let ((config (dashboard-network-config network)))
    (let ((topology (build-network-topology (dashboard-network-items config "/api/v1/pods")
                                            (dashboard-network-items config "/apis/apps/v1/replicasets")
                                            (dashboard-network-items config "/api/v1/services")
                                            (dashboard-network-items config "/api/v1/nodes")
                                            (loop for kind in '("httproutes" "grpcroutes" "tlsroutes" "tcproutes")
                                                  append (dashboard-network-items
                                                          config (format nil "/apis/gateway.networking.k8s.io/v1/~A" kind))))))
      (bt:with-lock-held ((network-graph-lock (dashboard-network-graph network)))
        (setf (network-graph-topology (dashboard-network-graph network)) topology)))))

(defun refresh-dashboard-network-favicons (network)
  "Fetch the favicon of each workload in the graph with a web UI, unless tried lately."
  (let* ((graph (dashboard-network-graph network))
         (now (get-universal-time))
         (due (bt:with-lock-held ((network-graph-lock graph))
                (loop for id being the hash-keys of (network-graph-nodes graph) using (hash-value node)
                      for endpoints = (gethash (first node) (network-topology-web (network-graph-topology graph)))
                      for cached = (bt:with-lock-held ((dashboard-network-favicons-lock network))
                                     (gethash id (dashboard-network-favicons network)))
                      when (and endpoints (or (null cached) (> (- now (first cached)) +network-favicon-retry-seconds+)))
                        collect (cons id endpoints)))))
    (loop for (id . endpoints) in due
          until (dashboard-network-stopping network)
          do (let ((found (loop for endpoint in endpoints
                                do (multiple-value-bind (octets type) (fetch-network-favicon (dashboard-network-config network) endpoint)
                                     (when octets (return (list octets type)))))))
               (bt:with-lock-held ((dashboard-network-favicons-lock network))
                 (setf (gethash id (dashboard-network-favicons network)) (list* now (or found (list nil nil)))))))))

(defun dashboard-network-favicon (network id)
  "(values octets content-type) of node ID's favicon, or NIL."
  (bt:with-lock-held ((dashboard-network-favicons-lock network))
    (let ((cached (gethash id (dashboard-network-favicons network))))
      (and cached (second cached) (values (second cached) (third cached))))))

(defun start-dashboard-network (network)
  "Start following the cluster's flows, once: when the tab is first opened."
  (bt:with-lock-held ((dashboard-network-lock network))
    (unless (dashboard-network-started network)
      (setf (dashboard-network-started network) t)
      (refresh-dashboard-network-topology network)
      (flet ((stopping () (dashboard-network-stopping network)))
        (setf (dashboard-network-threads network)
              (list
               (bt:make-thread
                (lambda ()
                  (loop until (stopping)
                        do (sleep 5)
                           (ignore-errors (refresh-dashboard-network-topology network))
                           (network-graph-expire (dashboard-network-graph network) (get-universal-time))))
                :name "gr8s network topology")
               (bt:make-thread
                (lambda ()
                  (loop until (stopping)
                        do (ignore-errors (refresh-dashboard-network-favicons network))
                           (loop repeat 100 until (stopping) do (sleep 0.1))))
                :name "gr8s network favicons")
               (bt:make-thread
                (lambda ()
                  ;; Recent flows, then new ones; when the stream ends, follow it again.
                  (loop until (stopping)
                        do (handler-case
                               (call-with-api-flows
                                (dashboard-network-config network) nil t
                                (lambda (line)
                                  (let ((flow (ignore-errors (com.inuoe.jzon:parse line))))
                                    (when (and (hash-table-p flow) (not (gethash "error" flow)))
                                      (network-graph-note-flow (dashboard-network-graph network) flow))))
                                :on-open (lambda (closer) (setf (dashboard-network-flows-closer network) closer)))
                             (error (condition)
                               (when *dashboard-verbose*
                                 (format *error-output* "gr8s network: flows: ~A~%" condition))))
                           (loop repeat 20 until (stopping) do (sleep 0.1))))
                :name "gr8s network flows")))))))

(defun stop-dashboard-network (network)
  (setf (dashboard-network-stopping network) t)
  (let ((closer (dashboard-network-flows-closer network)))
    (when closer (funcall closer)))
  (dolist (thread (dashboard-network-threads network))
    (ignore-errors (bt:join-thread thread))))

(defun dashboard-network-dispatch (network base request)
  "Serve the Network tab under BASE, /network/<token>/: the page, its scripts, the graph
and an edge's flows."
  (let ((rest (subseq (hunchentoot:script-name request)
                      (min (length base) (length (hunchentoot:script-name request))))))
    (setf (hunchentoot:header-out :cache-control) "no-store")
    (flet ((json (value)
             (setf (hunchentoot:content-type*) "application/json")
             (com.inuoe.jzon:stringify value)))
      (cond
        ((member rest '("" "index.html") :test #'equal)
         (setf (hunchentoot:content-type*) "text/html; charset=utf-8"
               (hunchentoot:header-out :referrer-policy) "no-referrer")
         +dashboard-network-html+)
        ((uiop:string-prefix-p "assets/" rest)
         (let ((asset (assoc (subseq rest 7) +dashboard-network-assets+ :test #'equal)))
           (if (and asset (second asset))
               (progn (setf (hunchentoot:content-type*) "text/javascript; charset=utf-8"
                            (hunchentoot:header-out :cache-control) "max-age=3600")
                      (second asset))
               (progn (setf (hunchentoot:return-code*) 404 (hunchentoot:content-type*) "text/plain")
                      "no such asset (run 'make graph-assets')"))))
        ((and (uiop:string-prefix-p "icons/" rest)
              (assoc (subseq rest 6) +network-icon-files+ :test #'equal))
         (setf (hunchentoot:content-type*) "image/svg+xml"
               (hunchentoot:header-out :cache-control) "max-age=86400")
         (second (assoc (subseq rest 6) +network-icon-files+ :test #'equal)))
        ((and (uiop:string-prefix-p "fonts/" rest)
              (assoc (subseq rest 6) +network-font-files+ :test #'equal))
         (setf (hunchentoot:content-type*) "font/woff2"
               (hunchentoot:header-out :cache-control) "max-age=86400")
         (second (assoc (subseq rest 6) +network-font-files+ :test #'equal)))
        ((equal rest "graph")
         (start-dashboard-network network)
         (json (network-graph-object (dashboard-network-graph network) (get-universal-time)
                                     (lambda (id) (dashboard-network-favicon network id)))))
        ((equal rest "favicon")
         (multiple-value-bind (octets type) (dashboard-network-favicon network (hunchentoot:get-parameter "node" request))
           (if octets
               (progn (setf (hunchentoot:content-type*) type
                            (hunchentoot:header-out :x-content-type-options) "nosniff"
                            ;; Inert even when opened as a document: an SVG's script never runs.
                            (hunchentoot:header-out :content-security-policy) "default-src 'none'; style-src 'unsafe-inline'; sandbox"
                            (hunchentoot:header-out :cache-control) "max-age=3600")
                      octets)
               (progn (setf (hunchentoot:return-code*) 404 (hunchentoot:content-type*) "text/plain") "no favicon"))))
        ((equal rest "flows")
         (let ((edge (hunchentoot:get-parameter "edge" request)))
           (json (coerce (if edge
                             (network-graph-edge-flows (dashboard-network-graph network) edge)
                             (network-graph-latest-flows (dashboard-network-graph network)))
                         'vector))))
        (t (setf (hunchentoot:return-code*) 404 (hunchentoot:content-type*) "text/plain") "not found")))))
