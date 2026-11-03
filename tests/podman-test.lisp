(in-package #:gr8s/tests)

(in-suite gr8s)

(defparameter *multi-container-pod-json*
  "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"workers\"},\"spec\":{\"containers\":[{\"name\":\"front\",\"image\":\"example.invalid/front:1\",\"command\":[\"serve\"],\"args\":[\"--once\"],\"env\":[{\"name\":\"MODE\",\"value\":\"test\"}],\"ports\":[{\"containerPort\":8080}]},{\"name\":\"sidecar\",\"image\":\"example.invalid/sidecar:2\"}]}}")

(defun fixed-runtime-pod ()
  (let ((pod (parse-pod *multi-container-pod-json*)))
    (setf (pod-uid pod) "ABC-123"
          (pod-resource-version pod) "7")
    pod))

(test podman-create-plan-uses-argument-vectors-and-ownership-labels
  (is
   (equal
    '(("podman" "pod" "create"
       "--name" "gr8s-abc-123"
       "--label" "io.gr8s.managed=true"
       "--label" "io.gr8s.uid=ABC-123"
       "--label" "io.gr8s.resource-version=7")
      ("podman" "create"
       "--pod" "gr8s-abc-123"
       "--name" "gr8s-abc-123-front"
       "--label" "io.gr8s.managed=true"
       "--label" "io.gr8s.uid=ABC-123"
       "--label" "io.gr8s.container=front"
       "--restart" "always"
       "--env" "MODE=test"
       "--expose" "8080"
       "example.invalid/front:1" "serve" "--once")
      ("podman" "create"
       "--pod" "gr8s-abc-123"
       "--name" "gr8s-abc-123-sidecar"
       "--label" "io.gr8s.managed=true"
       "--label" "io.gr8s.uid=ABC-123"
       "--label" "io.gr8s.container=sidecar"
       "--restart" "always"
       "example.invalid/sidecar:2")
      ("podman" "pod" "start" "gr8s-abc-123"))
    (podman-create-plan (fixed-runtime-pod)))))

(test podman-observation-parses-owned-pod-state
  (let* ((calls '())
         (runner (lambda (argv)
                   (push argv calls)
                   (values
                    "[{\"Id\":\"pod-id\",\"Name\":\"gr8s-abc-123\",\"Status\":\"Running\",\"Labels\":{\"io.gr8s.managed\":\"true\",\"io.gr8s.uid\":\"ABC-123\",\"io.gr8s.resource-version\":\"7\"}}]"
                    "" 0)))
         (runtime (make-podman-runtime :runner runner))
         (observed (runtime-observe runtime "ABC-123")))
    (is (string= "ABC-123" (runtime-pod-uid observed)))
    (is (string= "7" (runtime-pod-resource-version observed)))
    (is (equal '(("podman" "pod" "ps" "--filter"
                  "label=io.gr8s.uid=ABC-123" "--format" "json"))
               (reverse calls)))))

(test podman-delete-and-logs-target-only-an-observed-owned-pod
  (let ((calls '()))
    (flet ((runner (argv)
             (push argv calls)
             (cond
               ((equal (second argv) "pod")
                (if (equal (third argv) "ps")
                    (values "[{\"Id\":\"owned-id\",\"Name\":\"gr8s-abc-123\",\"Status\":\"Running\",\"Labels\":{\"io.gr8s.managed\":\"true\",\"io.gr8s.uid\":\"ABC-123\",\"io.gr8s.resource-version\":\"7\"}}]" "" 0)
                    (values "" "" 0)))
               ((equal (second argv) "logs")
                (values (format nil "hello~%") "" 0))
               (t (values "" "" 0)))))
      (let ((runtime (make-podman-runtime :runner #'runner)))
        (is (string= (format nil "hello~%")
                     (runtime-logs runtime "ABC-123" "front")))
        (runtime-delete runtime "ABC-123")
        (is (member '("podman" "logs" "gr8s-abc-123-front")
                    calls :test #'equal))
        (is (member '("podman" "pod" "rm" "--force" "owned-id")
                    calls :test #'equal))))))

(test podman-delete-never-removes-an-unmanaged-pod
  (let ((calls '()))
    (flet ((runner (argv)
             (push argv calls)
             (if (equal (subseq argv 1 3) '("pod" "ps"))
                 (values "[{\"Id\":\"unmanaged-id\",\"Status\":\"Running\",\"Labels\":{\"io.gr8s.uid\":\"ABC-123\"}}]"
                         "" 0)
                 (fail "gr8s tried to mutate an unmanaged Podman pod"))))
      (runtime-delete (make-podman-runtime :runner #'runner) "ABC-123")
      (is (= 1 (length calls))))))

(test podman-command-failures-are-typed-runtime-errors
  (let ((runtime
          (make-podman-runtime
           :runner (lambda (argv)
                     (declare (ignore argv))
                     (values "" "permission denied" 125)))))
    (handler-case
        (progn
          (runtime-observe runtime "ABC-123")
          (fail "Expected a runtime-error"))
      (runtime-error (error)
        (is (search "permission denied" (runtime-error-message error)))))))

(test podman-integration-creates-logs-and-removes-a-disposable-pod
  (if (string= "1" (or (uiop:getenv "GR8S_RUN_PODMAN_TESTS") ""))
      (let* ((pod (parse-pod
                   "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"integration\"},\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"docker.io/library/busybox:latest\",\"command\":[\"sh\",\"-c\"],\"args\":[\"echo gr8s-integration\"]}]}}"))
             (runtime (make-podman-runtime)))
        (setf (pod-uid pod) (format nil "integration-~36R" (random (expt 36 8)))
              (pod-resource-version pod) "1")
        (unwind-protect
             (progn
               (runtime-ensure runtime pod)
               (is (search "gr8s-integration"
                           (runtime-logs runtime (pod-uid pod) "main"))))
          (runtime-delete runtime (pod-uid pod))))
      (skip "Set GR8S_RUN_PODMAN_TESTS=1 to run the Podman integration test")))
