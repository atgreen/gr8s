(in-package #:gr8s)

(defun prometheus-label (value)
  (with-output-to-string (stream)
    (loop for character across value
          do (case character
               (#\\ (write-string "\\\\" stream))
               (#\" (write-string "\\\"" stream))
               (#\Newline (write-string "\\n" stream))
               (otherwise (write-char character stream))))))

(defmethod runtime-network-metrics ((runtime control-plane-runtime))
  (let* ((server (control-plane-runtime-node-server runtime))
         (statuses (bt:with-lock-held ((node-grpc-server-lock server))
                     (loop for name being the hash-keys of (node-grpc-server-statuses server)
                             using (hash-value status) collect (cons name status)))))
    (with-output-to-string (stream)
      (dolist (entry (sort statuses #'string< :key #'car))
        (let* ((name (car entry)) (status (cdr entry))
               (node (get-node (node-grpc-server-store server) name)))
          (format stream "gr8s_dataplane_node_ready{node=\"~A\"} ~D~%"
                  (prometheus-label name) (if (node-record-runtime-ready-p node) 1 0))
          (format stream "gr8s_dataplane_observed_timestamp_seconds{node=\"~A\"} ~D~%"
                  (prometheus-label name)
                  (floor (slot-value status 'gr8s.node.v1::observed-at-unix-nanos) 1000000000))
          (dolist (endpoint (slot-value status 'gr8s.node.v1::endpoints))
            (let ((labels
                    (format nil "node=\"~A\",sandbox=\"~A\",interface=\"~A\",pod_ip=\"~A\""
                            (prometheus-label name)
                            (prometheus-label (slot-value endpoint 'gr8s.node.v1::sandbox-id))
                            (prometheus-label (slot-value endpoint 'gr8s.node.v1::interface-name))
                            (prometheus-label (slot-value endpoint 'gr8s.node.v1::pod-ip))))
                  (available (string= "" (slot-value endpoint 'gr8s.node.v1::error-message))))
              (format stream "gr8s_endpoint_telemetry_available{~A} ~D~%" labels (if available 1 0))
              (when available
                (loop for (name slot) in
                      '(("allowed_packets" gr8s.node.v1::allowed-packets)
                        ("allowed_bytes" gr8s.node.v1::allowed-bytes)
                        ("dropped_packets" gr8s.node.v1::dropped-packets)
                        ("dropped_bytes" gr8s.node.v1::dropped-bytes)
                        ("rejected_spoofs" gr8s.node.v1::rejected-spoofs)
                        ("malformed_packets" gr8s.node.v1::malformed-packets)
                        ("unsupported_packets" gr8s.node.v1::unsupported-packets))
                      do (format stream "gr8s_endpoint_~A_total{~A} ~D~%"
                                 name labels (slot-value endpoint slot)))))))))))
