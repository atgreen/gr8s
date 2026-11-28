;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0

(in-package #:gr8s/tests)

(in-suite gr8-tenancy)

(defun gr8-user-socket-ask (path)
  "Connect to the gr8 user socket at PATH and return its parsed reply."
  (let ((socket (make-instance 'sb-bsd-sockets:local-socket :type :stream :protocol 0)))
    (sb-bsd-sockets:socket-connect socket path)
    (let ((stream (sb-bsd-sockets:socket-make-stream socket :input t :output t :element-type 'character
                                                            :external-format :utf-8)))
      (unwind-protect (com.inuoe.jzon:parse stream)
        (close stream)))))

(test a-local-user-gets-gr8-from-the-socket-as-who-the-kernel-says-they-are
  ;; podster-7uof: whoever connects is identified by SO_PEERCRED, never by what they
  ;; send, and gets their own namespace, grant and kubeconfig without sudo.
  (let* ((uid (sb-posix:getuid))
         (name (sb-posix:passwd-name (sb-posix:getpwuid uid)))
         (namespace (gr8s.server::gr8-user-namespace name))
         (identity (concatenate 'string "gr8:" name)))
    (if (or (< uid 1000) (not (gr8s.server::gr8-user-name-p name)))
        (skip "the test runs as a system account (UID ~D)" uid)
        (with-temporary-store (store path)
          (with-temporary-pki (pki root)
            (values root)
            (let* ((socket-path (namestring (merge-pathnames "run/gr8.sock" path)))
                   (server (gr8s.server::start-gr8-user-socket socket-path store pki "https://127.0.0.1:6443")))
              (unwind-protect
                   (let* ((reply (gr8-user-socket-ask socket-path))
                          (kubeconfig (gethash "kubeconfig" reply)))
                     (is (stringp kubeconfig) "the socket refused: ~A" (gethash "error" reply))
                     (when (stringp kubeconfig)
                       (is (search (format nil "namespace: ~A" namespace) kubeconfig))
                       (let* ((object (gr8s.resources::get-core-resource store "namespaces" nil namespace))
                              (annotations (gethash "annotations" (gethash "metadata" object))))
                         (is (equal identity (gethash "gr8s.io/gr8-owner" annotations)))
                         (is (equal (princ-to-string uid) (gethash "gr8s.io/gr8-uid" annotations)))
                         (is (search (princ-to-string (sb-posix:getgid)) (gethash "gr8s.io/gr8-gids" annotations)))
                         (is (equal "privileged" (gethash "pod-security.kubernetes.io/enforce"
                                                          (gethash "labels" (gethash "metadata" object))))))
                       (dolist (place `(("roles" ,namespace) ("rolebindings" ,namespace)
                                        ("clusterroles" nil) ("clusterrolebindings" nil)))
                         (finishes (gr8s.resources::get-core-resource
                                    store (first place) (second place) (concatenate 'string "gr8s:" identity))))
                       ;; Asking again renews the same grant rather than failing.
                       (is (stringp (gethash "kubeconfig" (gr8-user-socket-ask socket-path))))))
                (gr8s.server::stop-gr8-user-socket server))
              ;; A machine that gives gr8 to one group refuses anyone outside it.
              (let ((server (gr8s.server::start-gr8-user-socket socket-path store pki "https://127.0.0.1:6443"
                                                               :users-group "gr8s-test-no-such-group")))
                (unwind-protect
                     (is (search "not in group" (or (gethash "error" (gr8-user-socket-ask socket-path)) "")))
                  (gr8s.server::stop-gr8-user-socket server)))))))))

(test the-gr8-user-socket-refuses-system-accounts
  (with-temporary-store (store path)
    (values path)
    (with-temporary-pki (pki root)
      (values root)
      (dolist (uid '(0 1 999 60001 65534))
        (signals error (gr8s.server::issue-gr8-user-kubeconfig store pki "https://127.0.0.1:6443" uid 0))))))

(test the-servers-grant-to-a-gr8-user-is-what-gr8-calls-and-no-more
  ;; gr8's Go tests write every call gr8 makes to tests/fixtures/gr8-api-calls.json.
  (let* ((objects (gr8s.server::gr8-user-rbac "gr8:alice" "gr8-alice"))
         (role (third (find "roles" objects :key #'first :test #'equal)))
         (cluster-role (third (find "clusterroles" objects :key #'first :test #'equal)))
         (calls (com.inuoe.jzon:parse (asdf:system-relative-pathname :gr8s "tests/fixtures/gr8-api-calls.json"))))
    (flet ((grants-p (object group resource verb)
             (some (lambda (rule)
                     (and (find group (gethash "apiGroups" rule) :test #'equal)
                          (find resource (gethash "resources" rule) :test #'equal)
                          (find verb (gethash "verbs" rule) :test #'equal)))
                   (gethash "rules" object))))
      (is (plusp (length calls)))
      (loop for call across calls
            for group = (gethash "group" call) for resource = (gethash "resource" call)
            for verb = (gethash "verb" call)
            do (is (grants-p (if (gethash "namespaced" call) role cluster-role) group resource verb)
                   "gr8 calls ~A ~A/~A, which its grant doesn't allow" verb group resource))
      (loop for rule across (concatenate 'vector (gethash "rules" role) (gethash "rules" cluster-role))
            do (is (notany (lambda (list) (find "*" list :test #'equal))
                           (list (gethash "apiGroups" rule) (gethash "resources" rule) (gethash "verbs" rule))))
               (is (not (find "rbac.authorization.k8s.io" (gethash "apiGroups" rule) :test #'equal))))
      (is (not (grants-p cluster-role "" "pods" "get")))
      (is (not (grants-p cluster-role "" "secrets" "get")))
      (is (not (grants-p cluster-role "" "namespaces" "create")))
      (is (equalp #("gr8-alice")
                  (gethash "resourceNames" (find-if (lambda (rule) (find "namespaces" (gethash "resources" rule) :test #'equal))
                                                    (gethash "rules" cluster-role))))))))
