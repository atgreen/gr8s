;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; `gr8s status`: one screen of cluster health for a human or AI operator.
;;;; `gr8s doctor` asks whether this host can run gr8s; status asks what the
;;;; cluster is doing right now, from anywhere a kubeconfig reaches.  Each
;;;; section is a pure analyzer over fetched API JSON, unit-tested without a
;;;; cluster, and prints doctor-style [ ok ]/[warn]/[FAIL] lines whose hints
;;;; name the next command to run.

(in-package #:gr8s.server)

(defun status-get (object &rest path)
  (apply #'gr8s.apiserver::table-get object path))

(defun status-items (response)
  (coerce (or (and (hash-table-p response) (gethash "items" response)) #()) 'list))

(defun status-age (timestamp)
  (gr8s.apiserver::table-timestamp-age timestamp))

(defun make-status-check (name status detail &optional hint)
  (list :name name :status status :detail detail :hint hint))

(defun status-condition-true-p (object type)
  (loop for condition across (or (status-get object "status" "conditions") #())
        thereis (and (equal type (gethash "type" condition))
                     (equal "True" (gethash "status" condition)))))

(defun status-join-names (names &key (limit 4))
  (if (> (length names) limit)
      (format nil "~{~A~^, ~} and ~D more" (subseq names 0 limit) (- (length names) limit))
      (format nil "~{~A~^, ~}" names)))

;;; ---------------------------------------------------------------------------
;;; Pure analyzers.

(defun status-node-check (nodes)
  "Ready counts, unreachable nodes, and resource-pressure conditions."
  (let* ((total (length nodes))
         (not-ready (loop for node in nodes
                          unless (status-condition-true-p node "Ready")
                            collect (status-get node "metadata" "name")))
         (pressured (loop for node in nodes
                          when (some (lambda (type) (status-condition-true-p node type))
                                     '("MemoryPressure" "DiskPressure" "PIDPressure"))
                            collect (status-get node "metadata" "name"))))
    (cond
      ((zerop total)
       (make-status-check "nodes" :fail "no nodes registered"
                          "is an agent running? gr8s doctor on the host"))
      (not-ready
       (make-status-check "nodes"
                          :fail (format nil "~D/~D ready; not ready: ~A"
                                        (- total (length not-ready)) total
                                        (status-join-names not-ready))
                          (format nil "kubectl describe node ~A" (first not-ready))))
      (pressured
       (make-status-check "nodes"
                          :warn (format nil "~D/~D ready; pressure on ~A"
                                        total total (status-join-names pressured))
                          (format nil "kubectl describe node ~A" (first pressured))))
      (t (make-status-check "nodes" :ok (format nil "~D/~D ready; no pressure conditions"
                                                total total))))))

(defun status-pod-crashlooping-p (pod)
  (loop for container across (or (status-get pod "status" "containerStatuses") #())
        thereis (equal "CrashLoopBackOff"
                       (status-get container "state" "waiting" "reason"))))

(defun status-pod-restarts (pod)
  (loop for container across (or (status-get pod "status" "containerStatuses") #())
        sum (or (gethash "restartCount" container) 0)))

(defun status-controller-shortfalls (controllers kind)
  (loop for controller in controllers
        for desired = (if (equal kind "DaemonSet")
                          (status-get controller "status" "desiredNumberScheduled")
                          (status-get controller "spec" "replicas"))
        for ready = (or (if (equal kind "DaemonSet")
                            (status-get controller "status" "numberReady")
                            (status-get controller "status" "readyReplicas"))
                        0)
        when (and (integerp desired) (plusp desired) (< ready desired))
          collect (format nil "~A ~A/~A ~D/~D ready" kind
                          (status-get controller "metadata" "namespace")
                          (status-get controller "metadata" "name") ready desired)))

(defun status-workload-check (pods deployments statefulsets daemonsets)
  "Exceptions only: crashloops, stuck Pending, failures, controllers below desired."
  (let* ((running 0) (pending nil) (failed nil) (crashlooping nil))
    (dolist (pod pods)
      (let ((phase (status-get pod "status" "phase"))
            (name (format nil "~A/~A" (status-get pod "metadata" "namespace")
                          (status-get pod "metadata" "name"))))
        (cond
          ((status-pod-crashlooping-p pod)
           (push (format nil "~A (~D restarts)" name (status-pod-restarts pod)) crashlooping))
          ((equal phase "Running") (incf running))
          ((equal phase "Succeeded"))
          ((equal phase "Pending")
           (push (format nil "~A pending ~A" name
                         (status-age (status-get pod "metadata" "creationTimestamp")))
                 pending))
          ((equal phase "Failed") (push name failed)))))
    (let* ((shortfalls (append (status-controller-shortfalls deployments "Deployment")
                               (status-controller-shortfalls statefulsets "StatefulSet")
                               (status-controller-shortfalls daemonsets "DaemonSet")))
           (problems (append crashlooping failed pending shortfalls))
           (detail (if problems
                       (format nil "~D running; ~A" running (status-join-names problems))
                       (format nil "~D pods running, 0 pending, 0 failed" running))))
      (cond
        ((or failed crashlooping)
         (make-status-check "workloads" :warn detail
                            (let ((offender (first (or crashlooping (list nil)))))
                              (if offender
                                  (format nil "kubectl -n ~A logs ~A --previous --tail=200"
                                          (subseq offender 0 (position #\/ offender))
                                          (let* ((name (subseq offender (1+ (position #\/ offender)))))
                                            (subseq name 0 (position #\Space name))))
                                  "kubectl get pods -A --field-selector=status.phase=Failed"))))
        (problems (make-status-check "workloads" :warn detail
                                     "kubectl get pods -A | grep -v Running"))
        (t (make-status-check "workloads" :ok detail))))))

(defun status-service-check (services endpointslices &key gateways ingresses)
  "Selector-backed Services whose EndpointSlices hold no ready address."
  (let ((ready (make-hash-table :test #'equal)))
    (dolist (slice endpointslices)
      (let ((service (status-get slice "metadata" "labels" "kubernetes.io/service-name"))
            (namespace (status-get slice "metadata" "namespace")))
        (when (and service
                   (loop for endpoint across (or (gethash "endpoints" slice) #())
                         thereis (let ((conditions (gethash "conditions" endpoint)))
                                   ;; As upstream: a missing or null ready condition means ready.
                                   (if (hash-table-p conditions)
                                       (multiple-value-bind (value present) (gethash "ready" conditions)
                                         (or (not present) (eq value 'null) value))
                                       t))))
          (setf (gethash (cons namespace service) ready) t))))
    (let* ((empty (loop for service in services
                        for name = (status-get service "metadata" "name")
                        for namespace = (status-get service "metadata" "namespace")
                        when (and (status-get service "spec" "selector")
                                  (not (equal "ExternalName" (status-get service "spec" "type")))
                                  (not (gethash (cons namespace name) ready)))
                          collect (format nil "~A/~A" namespace name)))
           (routing (append
                     (when gateways
                       (list (format nil "~D/~D Gateways programmed"
                                     (count-if (lambda (gateway)
                                                 (status-condition-true-p gateway "Programmed"))
                                               gateways)
                                     (length gateways))))
                     (when ingresses (list (format nil "~D Ingresses" (length ingresses))))))
           (summary (format nil "~A~{; ~A~}"
                            (if empty
                                (format nil "~D Services without endpoints: ~A"
                                        (length empty) (status-join-names empty))
                                "0 Services without endpoints")
                            routing)))
      (if empty
          (make-status-check "networking" :warn summary
                             (let ((first-empty (first empty)))
                               (format nil "kubectl -n ~A describe service ~A"
                                       (subseq first-empty 0 (position #\/ first-empty))
                                       (subseq first-empty (1+ (position #\/ first-empty))))))
          (make-status-check "networking" :ok summary)))))

(defun status-storage-check (claims volumes)
  (let ((pending (loop for claim in claims
                       when (equal "Pending" (status-get claim "status" "phase"))
                         collect (format nil "~A/~A pending ~A"
                                         (status-get claim "metadata" "namespace")
                                         (status-get claim "metadata" "name")
                                         (status-age (status-get claim "metadata" "creationTimestamp")))))
        (failed (loop for volume in volumes
                      when (equal "Failed" (status-get volume "status" "phase"))
                        collect (status-get volume "metadata" "name"))))
    (cond
      ((or pending failed)
       (make-status-check "storage"
                          :warn (format nil "~@[PVC ~A~]~@[; PV failed: ~A~]"
                                        (and pending (status-join-names pending))
                                        (and failed (status-join-names failed)))
                          (if pending
                              (let* ((entry (first pending))
                                     (slash (position #\/ entry))
                                     (space (position #\Space entry)))
                                (format nil "kubectl -n ~A describe pvc ~A"
                                        (subseq entry 0 slash) (subseq entry (1+ slash) space)))
                              "kubectl describe pv")))
      ((null claims) (make-status-check "storage" :ok "no PersistentVolumeClaims"))
      (t (make-status-check "storage" :ok (format nil "all ~D PVCs bound" (length claims)))))))

(defun status-version-check (server-version nodes)
  (let* ((cluster (or (and server-version (gethash "gitVersion" server-version)) "unknown"))
         (skewed (loop for node in nodes
                       for version = (status-get node "status" "nodeInfo" "kubeletVersion")
                       unless (equal version cluster)
                         collect (format nil "~A at ~A" (status-get node "metadata" "name")
                                         (or version "unknown")))))
    (if skewed
        (make-status-check "versions"
                           :warn (format nil "server at ~A; ~A" cluster (status-join-names skewed))
                           "upgrade agents to the server's release")
        (make-status-check "versions"
                           :ok (format nil "all members and agents at ~A" cluster)))))

(defun status-event-timestamp (event)
  (or (status-get event "lastTimestamp") (status-get event "eventTime")
      (status-get event "metadata" "creationTimestamp")))

(defun status-warning-events (events &key (limit 5))
  "Deduplicated Warning events, newest first."
  (let ((deduplicated (make-hash-table :test #'equal)))
    (dolist (event events)
      (let* ((key (list (status-get event "involvedObject" "namespace")
                        (gethash "reason" event)
                        (status-get event "involvedObject" "kind")
                        (status-get event "involvedObject" "name")))
             (timestamp (status-event-timestamp event))
             (existing (gethash key deduplicated)))
        (when (or (null existing)
                  (string> (or timestamp "") (or (status-event-timestamp existing) "")))
          (setf (gethash key deduplicated) event))))
    (let ((latest (sort (loop for event being the hash-values of deduplicated collect event)
                        #'string> :key (lambda (event) (or (status-event-timestamp event) "")))))
      (values
       (loop for event in (subseq latest 0 (min limit (length latest)))
             collect (list :age (status-age (status-event-timestamp event))
                           :namespace (or (status-get event "involvedObject" "namespace") "-")
                           :reason (or (gethash "reason" event) "-")
                           :message (let ((message (or (gethash "message" event) "")))
                                      (if (> (length message) 90)
                                          (concatenate 'string (subseq message 0 87) "...")
                                          message))))
       (hash-table-count deduplicated)))))

(defun status-exit-code (checks)
  (cond ((find :fail checks :key (lambda (check) (getf check :status))) 2)
        ((find :warn checks :key (lambda (check) (getf check :status))) 1)
        (t 0)))

;;; ---------------------------------------------------------------------------
;;; Data gathering and rendering.

(defun status-api-probe (config)
  "Time a /readyz round trip; the body is plain text, not JSON."
  (multiple-value-bind (stream socket host port base-path) (open-debug-api-stream config)
    (unwind-protect
         (let ((started (get-internal-real-time)))
           (write-debug-http-request stream "GET" host port
                                     (concatenate 'string base-path "/readyz")
                                     (getf config :token))
           (multiple-value-bind (http-status headers)
               (gr8s.protocol::parse-http-response-head
                (gr8s.protocol::read-http-response-head stream))
             (declare (ignore headers))
             (values (= http-status 200)
                     (round (* 1000 (- (get-internal-real-time) started))
                            internal-time-units-per-second))))
      (ignore-errors (close stream))
      (ignore-errors (usocket:socket-close socket)))))

(defun status-fetch-items (config target)
  (status-items (debug-api-get-json config target)))

(defun collect-cluster-status (config)
  "Fetch and analyze; optional API groups are allowed to be absent."
  (multiple-value-bind (ready milliseconds) (status-api-probe config)
    (let* ((version (ignore-errors (debug-api-get-json config "/version")))
           (nodes (status-fetch-items config "/api/v1/nodes"))
           (pods (status-fetch-items config "/api/v1/pods?limit=5000"))
           (checks
             (list
              (make-status-check "api"
                                 (if ready :ok :fail)
                                 (format nil "/readyz ~:[failed~;ok~] in ~Dms" ready milliseconds)
                                 (unless ready "journalctl -u gr8s-server on the control plane"))
              (status-node-check nodes)
              (status-workload-check pods
                                     (status-fetch-items config "/apis/apps/v1/deployments")
                                     (status-fetch-items config "/apis/apps/v1/statefulsets")
                                     (status-fetch-items config "/apis/apps/v1/daemonsets"))
              (status-service-check
               (status-fetch-items config "/api/v1/services")
               (status-fetch-items config "/apis/discovery.k8s.io/v1/endpointslices")
               :gateways (ignore-errors
                          (status-fetch-items config "/apis/gateway.networking.k8s.io/v1/gateways"))
               :ingresses (ignore-errors
                           (status-fetch-items config "/apis/networking.k8s.io/v1/ingresses")))
              (status-storage-check (status-fetch-items config "/api/v1/persistentvolumeclaims")
                                    (status-fetch-items config "/api/v1/persistentvolumes"))
              (status-version-check version nodes))))
      (multiple-value-bind (events total-warnings)
          (status-warning-events
           (status-fetch-items config "/api/v1/events?fieldSelector=type%3DWarning&limit=500"))
        (list :server (getf config :server)
              :version (or (and version (gethash "gitVersion" version)) "unknown")
              :checks checks :events events :warnings total-warnings)))))

(defun print-status-text (status &optional (stream *standard-output*))
  (format stream "cluster: gr8s ~A    api: ~A~%~%"
          (getf status :version) (getf status :server))
  (dolist (check (getf status :checks))
    (format stream "  [~A] ~13A ~A~%"
            (ecase (getf check :status) (:ok " ok ") (:warn "warn") (:fail "FAIL"))
            (getf check :name) (getf check :detail))
    (when (and (getf check :hint) (member (getf check :status) '(:warn :fail)))
      (format stream "~20T-> ~A~%" (getf check :hint))))
  (let ((events (getf status :events)))
    (when events
      (format stream "~%  recent warnings (~D of ~D, deduplicated):~%"
              (length events) (getf status :warnings))
      (dolist (event events)
        (format stream "    ~6A ~12A ~20A ~A~%" (getf event :age) (getf event :namespace)
                (getf event :reason) (getf event :message)))))
  (let ((code (status-exit-code (getf status :checks))))
    (format stream "~%status: ~[healthy~;~D warning~:P~;failures present~]~%"
            code (count :warn (getf status :checks) :key (lambda (check) (getf check :status))))
    code))

(defun status-json (status)
  (json-object
   "server" (getf status :server)
   "version" (getf status :version)
   "checks" (coerce (loop for check in (getf status :checks)
                          collect (json-object "name" (getf check :name)
                                               "status" (string-downcase (getf check :status))
                                               "detail" (getf check :detail)
                                               "hint" (or (getf check :hint) 'null)))
                    'vector)
   "events" (coerce (loop for event in (getf status :events)
                          collect (json-object "age" (getf event :age)
                                               "namespace" (getf event :namespace)
                                               "reason" (getf event :reason)
                                               "message" (getf event :message)))
                    'vector)
   "warnings" (getf status :warnings)))

;;; ---------------------------------------------------------------------------
;;; CLI.

(defun parse-status-options (arguments)
  "Parse the cluster status overview."
  (let ((options (list :command :status
                       :kubeconfig (default-client-kubeconfig)
                       :output "text")))
    (loop while arguments
          for option = (first arguments)
          do (cond
               ((string= option "--kubeconfig")
                (setf (getf options :kubeconfig) (option-value arguments option)
                      arguments (cddr arguments)))
               ((string= option "--output")
                (let ((value (option-value arguments option)))
                  (unless (member value '("text" "json") :test #'equal)
                    (error "status --output must be text or json"))
                  (setf (getf options :output) value arguments (cddr arguments))))
               (t (error "unknown status option: ~A" option))))
    options))

(defun run-status-command (options &optional (output *standard-output*))
  "Print one screen of cluster health; exit 0 healthy, 1 warnings, 2 failures."
  (call-with-debug-kubeconfig
   (getf options :kubeconfig)
   (lambda (config) (run-status-command-with-config config options output))))

(defun run-status-command-with-config (config options output)
  (let* ((status (handler-case (collect-cluster-status config)
                   (error (condition)
                     (list :server (getf config :server) :version "unknown"
                           :checks (list (make-status-check
                                          "api" :fail
                                          (format nil "cannot reach the API: ~A" condition)
                                          "check the server address and credentials; journalctl -u gr8s-server"))
                           :events nil :warnings 0)))))
    (if (equal "json" (getf options :output))
        (progn
          (com.inuoe.jzon:stringify (status-json status) :stream output)
          (terpri output)
          (finish-output output)
          (status-exit-code (getf status :checks)))
        (print-status-text status output))))
