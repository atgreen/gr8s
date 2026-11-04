;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Verify downward API and projected volumes write the exact content Kubernetes
;;;; defines, and that refreshing a live volume changes only what differs while
;;;; keeping old content when a source cannot be read.

(in-package #:gr8s/tests)
(def-suite pod-volume-projection :in gr8s)
(in-suite pod-volume-projection)

(defun projection-pod (volumes-json &key (labels "{\"a\":\"1\",\"b\":\"two\\\"q\"}") (annotations "{\"note\":\"x\"}")
                                      (resources "{\"limits\":{\"cpu\":\"1250m\",\"memory\":\"64Mi\"},\"requests\":{\"cpu\":\"250m\",\"memory\":\"32Mi\"}}"))
  "Return an unsaved Pod in namespace sonobuoy with the VOLUMES-JSON array."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"projected\",\"namespace\":\"sonobuoy\",\"labels\":~A,\"annotations\":~A},\"spec\":{\"volumes\":~A,\"containers\":[{\"name\":\"client\",\"image\":\"busybox:latest\",\"resources\":~A}]}}" labels annotations volumes-json resources)))

(defmacro with-projection ((runtime store directory) &body body)
  "Run BODY with a containerd runtime whose resources come from a test store."
  `(with-temporary-store (,store ,directory)
     (create-volume-test-data ,store "sonobuoy")
     (let ((,runtime (gr8s::make-containerd-runtime :log-root (merge-pathnames "logs/" ,directory))))
       (setf (gr8s::containerd-runtime-resource-store ,runtime) ,store)
       ,@body)))

(defun materialized (runtime store pod &optional (index 0))
  "Create POD and return the directory of its volume at INDEX, freshly materialized."
  (let* ((created (create-pod store pod))
         (volume (aref (gethash "volumes" (gethash "spec" (pod-to-object created))) index)))
    (values (gr8s::materialize-pod-volume runtime created volume) created)))

(defun volume-text (directory relative)
  "Read a volume file as text."
  (uiop:read-file-string (merge-pathnames relative directory)))

(defun projected-file-mode (directory relative)
  "Return a volume file's permission bits."
  (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring (merge-pathnames relative directory))))))

(defparameter *downward-volume*
  "[{\"name\":\"info\",\"downwardAPI\":{\"defaultMode\":420,\"items\":[
    {\"path\":\"podname\",\"fieldRef\":{\"apiVersion\":\"v1\",\"fieldPath\":\"metadata.name\"}},
    {\"path\":\"labels\",\"fieldRef\":{\"fieldPath\":\"metadata.labels\"}},
    {\"path\":\"note\",\"fieldRef\":{\"fieldPath\":\"metadata.annotations['note']\"}},
    {\"path\":\"secret-mode\",\"mode\":256,\"fieldRef\":{\"fieldPath\":\"metadata.namespace\"}},
    {\"path\":\"cpu_limit\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"limits.cpu\"}},
    {\"path\":\"cpu_limit_milli\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"limits.cpu\",\"divisor\":\"1m\"}},
    {\"path\":\"cpu_request\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"requests.cpu\",\"divisor\":\"0\"}},
    {\"path\":\"memory_limit\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"limits.memory\"}},
    {\"path\":\"memory_request_mi\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"requests.memory\",\"divisor\":\"1Mi\"}}]}}]")

(test downward-volume-files-match-kubernetes-formats
  (with-projection (runtime store directory)
    (values directory)
    (let ((path (materialized runtime store (projection-pod *downward-volume*))))
      (is (equal "projected" (volume-text path "podname")))
      (is (equal (format nil "a=\"1\"~%b=\"two\\\"q\"") (volume-text path "labels")))
      (is (equal "x" (volume-text path "note")))
      (is (equal "sonobuoy" (volume-text path "secret-mode")))
      (is (= #o400 (projected-file-mode path "secret-mode")))
      (is (= #o644 (projected-file-mode path "podname")))
      ;; Values from the upstream specs: 1250m rounds up to 2, 250m to 1.
      (is (equal "2" (volume-text path "cpu_limit")))
      (is (equal "1250" (volume-text path "cpu_limit_milli")))
      (is (equal "1" (volume-text path "cpu_request")))
      (is (equal "67108864" (volume-text path "memory_limit")))
      (is (equal "32" (volume-text path "memory_request_mi"))))))

(test unset-limits-report-node-allocatable-and-unset-requests-zero
  (with-projection (runtime store directory)
    (values directory)
    (let ((path (materialized
                 runtime store
                 (projection-pod "[{\"name\":\"info\",\"downwardAPI\":{\"items\":[
                    {\"path\":\"cpu\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"limits.cpu\"}},
                    {\"path\":\"memory\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"limits.memory\"}},
                    {\"path\":\"request\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"requests.cpu\"}}]}}]"
                                 :resources "{}"))))
      (is (= (gr8s::node-allocatable-cpu) (parse-integer (volume-text path "cpu"))))
      (is (plusp (gr8s::node-allocatable-cpu)))
      (is (= (gr8s::node-allocatable-memory) (parse-integer (volume-text path "memory"))))
      (is (equal "0" (volume-text path "request"))))))

(defparameter *projected-volume*
  "[{\"name\":\"all\",\"projected\":{\"defaultMode\":416,\"sources\":[
    {\"configMap\":{\"name\":\"settings\",\"items\":[{\"key\":\"message\",\"path\":\"cfg/message\"}]}},
    {\"secret\":{\"name\":\"credentials\",\"items\":[{\"key\":\"binary\",\"path\":\"sec/binary\",\"mode\":256}]}},
    {\"downwardAPI\":{\"items\":[{\"path\":\"podname\",\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}]}},
    {\"configMap\":{\"name\":\"absent\",\"optional\":true}}]}}]")

(test projected-volumes-combine-sources-in-one-directory
  (with-projection (runtime store directory)
    (values directory)
    (let ((path (materialized runtime store (projection-pod *projected-volume*))))
      (is (equal "hello projection" (volume-text path "cfg/message")))
      (is (equalp #(0 255) (gr8s::read-file-octets (merge-pathnames "sec/binary" path))))
      (is (equal "projected" (volume-text path "podname")))
      (is (= #o640 (projected-file-mode path "podname")))
      (is (= #o400 (projected-file-mode path "sec/binary"))))))

(test projected-references-reach-the-agent
  (let ((declared (gr8s::pod-resource-reference-declarations (projection-pod *projected-volume*))))
    (is (member '("configmaps" "settings" nil) declared :test #'equal))
    (is (member '("secrets" "credentials" nil) declared :test #'equal))
    (is (member '("configmaps" "absent" t) declared :test #'equal))))

(test downward-and-projected-mounts-are-read-only
  (with-projection (runtime store directory)
    (values directory)
    (let* ((input (projection-pod "[{\"name\":\"down\",\"downwardAPI\":{\"items\":[{\"path\":\"n\",\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}]}},
                                    {\"name\":\"proj\",\"projected\":{\"sources\":[{\"downwardAPI\":{\"items\":[{\"path\":\"m\",\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}]}}]}}]"))
           (container (aref (gethash "containers" (gethash "spec" (pod-to-object input))) 0)))
      (setf (gethash "volumeMounts" container)
            (vector (gr8s::core-object "name" "down" "mountPath" "/down")
                    (gr8s::core-object "name" "proj" "mountPath" "/proj")))
      (let* ((pod (create-pod store (parse-pod (pod-to-object input))))
             (mounts (gr8s::containerd-pod-mounts runtime pod (aref (pod-containers pod) 0))))
        (is (= 2 (length mounts)))
        (is (every #'gr8s.cri.v1::readonly mounts))))))

(test refresh-applies-label-and-object-changes-to-a-live-volume
  (with-projection (runtime store directory)
    (values directory)
    (multiple-value-bind (path pod)
        (materialized runtime store
                      (projection-pod "[{\"name\":\"all\",\"projected\":{\"sources\":[
                         {\"configMap\":{\"name\":\"settings\"}},
                         {\"downwardAPI\":{\"items\":[{\"path\":\"labels\",\"fieldRef\":{\"fieldPath\":\"metadata.labels\"}}]}}]}}]"
                                      :labels "{\"a\":\"1\"}"))
      (is (equal "a=\"1\"" (volume-text path "labels")))
      (is (equal "hello projection" (volume-text path "message")))
      (setf (gethash "a" (gethash "labels" (gethash "metadata" (pod-to-object pod)))) "changed")
      (gr8s::update-core-resource store "configmaps" "sonobuoy" "settings"
        (lambda (current)
          (setf (gethash "data" current) (gr8s::core-object "renamed" "new value"))
          current))
      (gr8s::refresh-pod-projected-volumes runtime pod)
      (is (equal "a=\"changed\"" (volume-text path "labels")))
      (is (equal "new value" (volume-text path "renamed")))
      ;; A key removed from the object disappears from the volume.
      (is (null (probe-file (merge-pathnames "message" path)))))))

(test refresh-leaves-unchanged-files-alone
  (with-projection (runtime store directory)
    (values directory)
    (multiple-value-bind (path pod) (materialized runtime store (projection-pod *projected-volume*))
      (let* ((file (namestring (merge-pathnames "podname" path)))
             (inode (sb-posix:stat-ino (sb-posix:stat file))))
        (gr8s::refresh-pod-projected-volumes runtime pod)
        (is (= inode (sb-posix:stat-ino (sb-posix:stat file))))))))

(test optional-objects-appear-and-disappear-with-their-source
  (with-projection (runtime store directory)
    (values directory)
    (multiple-value-bind (path pod)
        (materialized runtime store
                      (projection-pod "[{\"name\":\"opt\",\"configMap\":{\"name\":\"later\",\"optional\":true}}]"))
      (is (null (gr8s::volume-directory-files path)))
      (gr8s::create-core-resource store "configmaps"
        (gr8s::core-object "metadata" (gr8s::core-object "name" "later") "data" (gr8s::core-object "k" "v")) "sonobuoy")
      (gr8s::refresh-pod-projected-volumes runtime pod)
      (is (equal "v" (volume-text path "k")))
      (gr8s::delete-core-resource store "configmaps" "sonobuoy" "later")
      (gr8s::refresh-pod-projected-volumes runtime pod)
      (is (null (gr8s::volume-directory-files path))))))

(test a-failing-source-keeps-the-last-good-content
  (with-projection (runtime store directory)
    (values directory)
    (multiple-value-bind (path pod)
        (materialized runtime store (projection-pod "[{\"name\":\"cfg\",\"configMap\":{\"name\":\"settings\"}}]"))
      (gr8s::delete-core-resource store "configmaps" "sonobuoy" "settings")
      (let ((*error-output* (make-broadcast-stream)))
        (gr8s::refresh-pod-projected-volumes runtime pod))
      (is (equal "hello projection" (volume-text path "message"))))))

(test unimplemented-or-invalid-projections-are-refused
  (dolist (volume '("[{\"name\":\"v\",\"projected\":{\"sources\":[{\"serviceAccountToken\":{\"path\":\"t\",\"expirationSeconds\":3600}}]}}]"
                    "[{\"name\":\"v\",\"projected\":{\"sources\":[{\"clusterTrustBundle\":{\"path\":\"t\"}}]}}]"
                    "[{\"name\":\"v\",\"downwardAPI\":{\"items\":[{\"path\":\"../x\",\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}]}}]"
                    "[{\"name\":\"v\",\"downwardAPI\":{\"items\":[{\"path\":\"x\"}]}}]"
                    "[{\"name\":\"v\",\"downwardAPI\":{\"items\":[{\"path\":\"x\",\"fieldRef\":{\"fieldPath\":\"status.podIP\"}}]}}]"
                    "[{\"name\":\"v\",\"downwardAPI\":{\"items\":[{\"path\":\"x\",\"resourceFieldRef\":{\"containerName\":\"client\",\"resource\":\"limits.nvidia.com/gpu\"}}]}}]"
                    "[{\"name\":\"v\",\"downwardAPI\":{\"defaultMode\":4096,\"items\":[]}}]"
                    "[{\"name\":\"v\",\"projected\":{\"sources\":[{\"downwardAPI\":{\"items\":[{\"path\":\"same\",\"fieldRef\":{\"fieldPath\":\"metadata.name\"}}]}},{\"configMap\":{\"name\":\"c\",\"items\":[{\"key\":\"k\",\"path\":\"same\"}]}}]}}]"))
    (signals kubernetes-error (projection-pod volume))))

(test go-quoting-matches-kubernetes-for-metadata-values
  (is (equal "\"plain\"" (gr8s::go-quoted-string "plain")))
  (is (equal "\"a\\\"b\\\\c\\nd\"" (gr8s::go-quoted-string (format nil "a\"b\\c~%d"))))
  (is (equal "" (gr8s::format-downward-map nil))))
