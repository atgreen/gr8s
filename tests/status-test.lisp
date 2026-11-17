;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
(in-package #:gr8s/tests)
(def-suite cluster-status :in gr8s)
(in-suite cluster-status)

(defun status-fixture (json)
  "Parse a fixture exactly as the API client does, booleans and nulls included."
  (com.inuoe.jzon:parse json))

(defun status-fixture-items (json)
  (coerce (gethash "items" (status-fixture json)) 'list))

(defun check-field (check field) (getf check field))

(test node-check-distinguishes-ready-pressure-and-absent
  (let ((ready "{\"items\":[
          {\"metadata\":{\"name\":\"cp1\"},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}},
          {\"metadata\":{\"name\":\"w1\"},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}}]}")
        (lost "{\"items\":[
          {\"metadata\":{\"name\":\"cp1\"},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}},
          {\"metadata\":{\"name\":\"w1\"},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"Unknown\"}]}}]}")
        (pressured "{\"items\":[
          {\"metadata\":{\"name\":\"cp1\"},\"status\":{\"conditions\":[
            {\"type\":\"Ready\",\"status\":\"True\"},{\"type\":\"MemoryPressure\",\"status\":\"True\"}]}}]}"))
    (let ((check (gr8s.server::status-node-check (status-fixture-items ready))))
      (is (eq :ok (check-field check :status)))
      (is (search "2/2 ready" (check-field check :detail))))
    (let ((check (gr8s.server::status-node-check (status-fixture-items lost))))
      (is (eq :fail (check-field check :status)))
      (is (search "not ready: w1" (check-field check :detail)))
      (is (search "describe node w1" (check-field check :hint))))
    (let ((check (gr8s.server::status-node-check (status-fixture-items pressured))))
      (is (eq :warn (check-field check :status)))
      (is (search "pressure on cp1" (check-field check :detail))))
    (is (eq :fail (check-field (gr8s.server::status-node-check nil) :status)))))

(test workload-check-reports-only-exceptions
  (let ((healthy (status-fixture-items "{\"items\":[
          {\"metadata\":{\"namespace\":\"a\",\"name\":\"p1\"},\"status\":{\"phase\":\"Running\"}},
          {\"metadata\":{\"namespace\":\"a\",\"name\":\"done\"},\"status\":{\"phase\":\"Succeeded\"}}]}"))
        (crashing (status-fixture-items "{\"items\":[
          {\"metadata\":{\"namespace\":\"web\",\"name\":\"api-1\"},\"status\":{\"phase\":\"Running\",
            \"containerStatuses\":[{\"restartCount\":14,
              \"state\":{\"waiting\":{\"reason\":\"CrashLoopBackOff\"}}}]}}]}"))
        (short (status-fixture-items "{\"items\":[
          {\"metadata\":{\"namespace\":\"web\",\"name\":\"api\"},
           \"spec\":{\"replicas\":3},\"status\":{\"readyReplicas\":1}}]}")))
    (let ((check (gr8s.server::status-workload-check healthy nil nil nil)))
      (is (eq :ok (check-field check :status)))
      (is (search "1 pods running, 0 pending, 0 failed" (check-field check :detail))))
    (let ((check (gr8s.server::status-workload-check crashing nil nil nil)))
      (is (eq :warn (check-field check :status)))
      (is (search "web/api-1 (14 restarts)" (check-field check :detail)))
      (is (search "kubectl -n web logs api-1 --previous" (check-field check :hint))))
    (let ((check (gr8s.server::status-workload-check nil short nil nil)))
      (is (eq :warn (check-field check :status)))
      (is (search "Deployment web/api 1/3 ready" (check-field check :detail))))))

(test service-check-flags-selector-services-without-ready-endpoints
  (let ((services (status-fixture-items "{\"items\":[
          {\"metadata\":{\"namespace\":\"a\",\"name\":\"served\"},\"spec\":{\"selector\":{\"app\":\"x\"}}},
          {\"metadata\":{\"namespace\":\"a\",\"name\":\"empty\"},\"spec\":{\"selector\":{\"app\":\"y\"}}},
          {\"metadata\":{\"namespace\":\"a\",\"name\":\"manual\"},\"spec\":{}},
          {\"metadata\":{\"namespace\":\"a\",\"name\":\"ext\"},
           \"spec\":{\"selector\":{\"app\":\"z\"},\"type\":\"ExternalName\"}}]}"))
        (slices (status-fixture-items "{\"items\":[
          {\"metadata\":{\"namespace\":\"a\",
            \"labels\":{\"kubernetes.io/service-name\":\"served\"}},
           \"endpoints\":[{\"addresses\":[\"10.0.0.1\"],\"conditions\":{\"ready\":true}}]},
          {\"metadata\":{\"namespace\":\"a\",
            \"labels\":{\"kubernetes.io/service-name\":\"empty\"}},
           \"endpoints\":[{\"addresses\":[\"10.0.0.2\"],\"conditions\":{\"ready\":false}}]}]}")))
    (let ((check (gr8s.server::status-service-check services slices)))
      (is (eq :warn (check-field check :status)))
      (is (search "1 Services without endpoints: a/empty" (check-field check :detail)))
      (is (search "kubectl -n a describe service empty" (check-field check :hint))))
    ;; A ready:null or missing condition counts as ready, as upstream treats it.
    (let* ((null-ready (status-fixture-items "{\"items\":[
            {\"metadata\":{\"namespace\":\"a\",
              \"labels\":{\"kubernetes.io/service-name\":\"empty\"}},
             \"endpoints\":[{\"addresses\":[\"10.0.0.2\"],\"conditions\":{\"ready\":null}}]}]}"))
           (check (gr8s.server::status-service-check services (append slices null-ready))))
      (is (eq :ok (check-field check :status)))
      (is (search "0 Services without endpoints" (check-field check :detail))))
    (let ((check (gr8s.server::status-service-check
                  services slices
                  :gateways (status-fixture-items "{\"items\":[
                    {\"metadata\":{\"name\":\"g\"},\"status\":{\"conditions\":[
                      {\"type\":\"Programmed\",\"status\":\"True\"}]}}]}")
                  :ingresses (status-fixture-items "{\"items\":[{\"metadata\":{\"name\":\"i\"}}]}"))))
      (is (search "1/1 Gateways programmed" (check-field check :detail)))
      (is (search "1 Ingresses" (check-field check :detail))))))

(test storage-check-reports-pending-claims-and-failed-volumes
  (let ((claims (status-fixture-items "{\"items\":[
          {\"metadata\":{\"namespace\":\"db\",\"name\":\"data-0\",
            \"creationTimestamp\":\"2026-11-16T00:00:00Z\"},\"status\":{\"phase\":\"Pending\"}},
          {\"metadata\":{\"namespace\":\"db\",\"name\":\"data-1\"},\"status\":{\"phase\":\"Bound\"}}]}"))
        (volumes (status-fixture-items "{\"items\":[
          {\"metadata\":{\"name\":\"pv-1\"},\"status\":{\"phase\":\"Failed\"}}]}")))
    (let ((check (gr8s.server::status-storage-check claims volumes)))
      (is (eq :warn (check-field check :status)))
      (is (search "db/data-0 pending" (check-field check :detail)))
      (is (search "pv-1" (check-field check :detail)))
      (is (search "kubectl -n db describe pvc data-0" (check-field check :hint))))
    (is (eq :ok (check-field (gr8s.server::status-storage-check nil nil) :status)))))

(test version-check-reports-member-and-agent-skew
  (let ((version (status-fixture "{\"gitVersion\":\"v1.37.2-gr8s.0\"}"))
        (matched (status-fixture-items "{\"items\":[
          {\"metadata\":{\"name\":\"cp1\"},
           \"status\":{\"nodeInfo\":{\"kubeletVersion\":\"v1.37.2-gr8s.0\"}}}]}"))
        (skewed (status-fixture-items "{\"items\":[
          {\"metadata\":{\"name\":\"old\"},
           \"status\":{\"nodeInfo\":{\"kubeletVersion\":\"v1.37.1-gr8s.9\"}}}]}")))
    (is (eq :ok (check-field (gr8s.server::status-version-check version matched) :status)))
    (let ((check (gr8s.server::status-version-check version skewed)))
      (is (eq :warn (check-field check :status)))
      (is (search "old at v1.37.1-gr8s.9" (check-field check :detail))))))

(test control-plane-check-flags-a-member-stuck-in-application-restore
  (flet ((check (&rest members) (gr8s.server::status-control-plane-check members)))
    ;; All ready (or unreachable/unprobed, which are not faults) -> ok.
    (is (eq :ok (check-field (check '(:name "a" :readyz :ready)
                                    '(:name "b" :readyz :unreachable)
                                    '(:name "c" :readyz :unprobed)) :status)))
    ;; No membership API (single control plane) -> ok.
    (is (eq :ok (check-field (gr8s.server::status-control-plane-check nil) :status)))
    ;; A member whose /readyz 503s (store access blocked by an interrupted
    ;; restore) -> warn naming it, with the restart remedy (podster-ftb).
    (let ((check (check '(:name "gr8s2" :readyz :restoring) '(:name "leader" :readyz :ready))))
      (is (eq :warn (check-field check :status)))
      (is (search "gr8s2" (check-field check :detail)))
      (is (search "application restore" (check-field check :detail)))
      (is (search "systemctl restart gr8s-server" (check-field check :hint))))))

(test warning-events-deduplicate-cap-and-order-newest-first
  (let ((events (status-fixture-items "{\"items\":[
          {\"reason\":\"BackOff\",\"message\":\"older\",\"lastTimestamp\":\"2026-11-16T10:00:00Z\",
           \"involvedObject\":{\"namespace\":\"web\",\"kind\":\"Pod\",\"name\":\"api\"}},
          {\"reason\":\"BackOff\",\"message\":\"newer\",\"lastTimestamp\":\"2026-11-16T11:00:00Z\",
           \"involvedObject\":{\"namespace\":\"web\",\"kind\":\"Pod\",\"name\":\"api\"}},
          {\"reason\":\"FailedScheduling\",\"message\":\"no capacity\",
           \"lastTimestamp\":\"2026-11-16T09:00:00Z\",
           \"involvedObject\":{\"namespace\":\"db\",\"kind\":\"Pod\",\"name\":\"pg-0\"}}]}")))
    (multiple-value-bind (latest total) (gr8s.server::status-warning-events events :limit 5)
      (is (= 2 total))
      (is (= 2 (length latest)))
      (is (equal "newer" (getf (first latest) :message)))
      (is (equal "BackOff" (getf (first latest) :reason)))
      (is (equal "FailedScheduling" (getf (second latest) :reason))))
    (multiple-value-bind (latest total) (gr8s.server::status-warning-events events :limit 1)
      (is (= 2 total))
      (is (= 1 (length latest))))))

(test status-rendering-and-exit-codes-cover-all-severities
  (let ((status (list :server "https://10.0.0.1:6443" :version "v1.37.2-gr8s.0"
                      :checks (list (gr8s.server::make-status-check "api" :ok "/readyz ok in 4ms")
                                    (gr8s.server::make-status-check
                                     "nodes" :warn "pressure on w1" "kubectl describe node w1"))
                      :events (list (list :age "12m" :namespace "db"
                                          :reason "FailedScheduling" :message "no capacity"))
                      :warnings 11)))
    (let ((text (with-output-to-string (out)
                  (is (= 1 (gr8s.server::print-status-text status out))))))
      (is (search "cluster: gr8s v1.37.2-gr8s.0" text))
      (is (search "[ ok ] api" text))
      (is (search "[warn] nodes" text))
      (is (search "-> kubectl describe node w1" text))
      (is (search "recent warnings (1 of 11" text))
      (is (search "status: 1 warning" text)))
    (let ((rendered (com.inuoe.jzon:parse
                     (com.inuoe.jzon:stringify (gr8s.server::status-json status)))))
      (is (equal "v1.37.2-gr8s.0" (gethash "version" rendered)))
      (is (= 2 (length (gethash "checks" rendered))))
      (is (equal "warn" (gethash "status" (aref (gethash "checks" rendered) 1))))
      (is (equal "no capacity" (gethash "message" (aref (gethash "events" rendered) 0)))))
    (is (= 0 (gr8s.server::status-exit-code
              (list (gr8s.server::make-status-check "api" :ok "fine")))))
    (is (= 2 (gr8s.server::status-exit-code
              (list (gr8s.server::make-status-check "api" :warn "slow")
                    (gr8s.server::make-status-check "nodes" :fail "gone")))))))

(test status-cli-parses-and-is-discoverable
  (let ((options (gr8s.server::parse-status-options '("--kubeconfig" "/k" "--output" "json"))))
    (is (eq :status (getf options :command)))
    (is (equal "/k" (getf options :kubeconfig)))
    (is (equal "json" (getf options :output))))
  (is (equal "text" (getf (gr8s.server::parse-status-options nil) :output)))
  (signals error (gr8s.server::parse-status-options '("--output" "yaml")))
  (signals error (gr8s.server::parse-status-options '("--unknown")))
  (dolist (arguments '(("help") ("help" "status") ("status" "--help")))
    (let ((output (with-output-to-string (*standard-output*)
                    (is (= 0 (gr8s.server::main-with-environment
                              arguments (constantly nil) (constantly 99)))))))
      (is (search "status" output)))))
