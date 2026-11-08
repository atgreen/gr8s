;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify imagePullSecrets reach the node, match images as the kubelet's keyring
;;;; does, are tried in order, and never let one credential's pull serve another's.

(in-package #:gr8s/tests)
(in-suite pod-volumes)

(defun base64-text (text)
  (ag-grpc:base64-encode (trivial-utf-8:string-to-utf-8-bytes text)))

(defun create-pull-secret (store name config &key (type "kubernetes.io/dockerconfigjson") (key ".dockerconfigjson"))
  "Create pull Secret NAME in the sonobuoy namespace holding the JSON text CONFIG."
  (gr8s::create-core-resource
   store "secrets"
   (gr8s::core-object "metadata" (gr8s::core-object "name" name) "type" type
                      "data" (gr8s::core-object key (base64-text config)))
   "sonobuoy"))

(defun pull-secret-test-pod (&rest names)
  "Return a Pod in the sonobuoy namespace that names pull Secrets NAMES."
  (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"private\",\"namespace\":\"sonobuoy\",\"uid\":\"private-uid\"},\"spec\":{\"imagePullSecrets\":[~{{\"name\":~S}~^,~}],\"containers\":[{\"name\":\"c\",\"image\":\"registry.example.test/a/b:1\"}]}}" names)))

(defmacro with-pull-credentials ((lookup store) &body body)
  "Run BODY with LOOKUP returning a Pod's credentials for an image, read from a fresh STORE."
  (let ((directory (gensym "DIRECTORY")) (runtime (gensym "RUNTIME")))
    `(with-temporary-store (,store ,directory)
       (let ((,runtime (gr8s::make-containerd-runtime :log-root (merge-pathnames "logs/" ,directory))))
         (setf (gr8s::containerd-runtime-resource-store ,runtime) ,store)
         (flet ((,lookup (image &rest names)
                  (gr8s::pod-image-pull-credentials ,runtime (apply #'pull-secret-test-pod names) "c" image)))
           ,@body)))))

(test image-names-normalize-to-their-repository
  (loop for (image repository) in '(("a" "docker.io/library/a")
                                    ("a:1" "docker.io/library/a")
                                    ("a/b:1" "docker.io/a/b")
                                    ("docker.io/a:1" "docker.io/library/a")
                                    ("index.docker.io/a/b" "docker.io/a/b")
                                    ("registry.example.test/a/b:1" "registry.example.test/a/b")
                                    ("registry:5000/a:1" "registry:5000/a")
                                    ("localhost/a" "localhost/a")
                                    ("ghcr.io/a/b@sha256:abc" "ghcr.io/a/b"))
        do (is (equal repository (gr8s::image-repository image)) "~A" image)))

(test docker-config-locations-reduce-to-a-host-and-path
  (loop for (location key) in '(("https://index.docker.io/v1/" "index.docker.io")
                                ("registry.example.test" "registry.example.test")
                                ("http://registry.example.test/v2/" "registry.example.test")
                                ("registry.example.test/team" "registry.example.test/team")
                                ("https://registry.example.test/v2/team/" "registry.example.test/team/"))
        do (is (equal key (gr8s::docker-config-key location)) "~A" location)))

(test registry-keys-match-by-host-shape-port-and-path-prefix
  (loop for (key repository expected) in '(("registry.example.test" "registry.example.test/a" t)
                                           ("*.example.test" "registry.example.test/a" t)
                                           ("reg*.example.test" "registry.example.test/a" t)
                                           ("regist?y.example.test" "registry.example.test/a" t)
                                           ("*.test" "registry.example.test/a" nil)
                                           ("*.example.test" "other.test/a" nil)
                                           ("registry.example.test:5000" "registry.example.test/a" nil)
                                           ("registry.example.test" "registry.example.test:5000/a" nil)
                                           ("registry.example.test:5000" "registry.example.test:5000/a" t)
                                           ("registry.example.test/team" "registry.example.test/team/a" t)
                                           ("registry.example.test/team" "registry.example.test/other/a" nil))
        do (is (eq expected (gr8s::registry-key-matches-p key repository)) "~A ~A" key repository)))

(test pull-secrets-yield-credentials-for-matching-images-only
  (with-pull-credentials (lookup store)
    (create-pull-secret store "reg" (format nil "{\"auths\":{\"registry.example.test\":{\"username\":\"u\",\"password\":\"p\"},\"https://index.docker.io/v1/\":{\"auth\":~S}}}"
                                            (base64-text "hub:se:cret")))
    (is (equal '(("u" . "p")) (lookup "registry.example.test/a/b:1" "reg")))
    (is (null (lookup "other.example.test/a:1" "reg")) "another registry is pulled anonymously")
    (is (equal '(("hub" . "se:cret")) (lookup "busybox:1" "reg")) "only the first colon separates the password")
    (is (equal '(("hub" . "se:cret")) (lookup "docker.io/a/b" "reg")))))

(test pull-secrets-accept-both-formats-and-unpadded-auth
  (with-pull-credentials (lookup store)
    (create-pull-secret store "old" (format nil "{\"registry.example.test\":{\"auth\":~S}}"
                                            (string-right-trim "=" (base64-text "o:p")))
                        :type "kubernetes.io/dockercfg" :key ".dockercfg")
    (is (equal '(("o" . "p")) (lookup "registry.example.test/a" "old")))
    (gr8s::create-core-resource store "secrets"
      (gr8s::core-object "metadata" (gr8s::core-object "name" "opaque")
                         "data" (gr8s::core-object ".dockerconfigjson" (base64-text "{}"))) "sonobuoy")
    (is (null (lookup "registry.example.test/a" "opaque")) "another type of Secret isn't a pull secret")))

(test more-specific-credentials-are-tried-first-across-secrets
  (with-pull-credentials (lookup store)
    (create-pull-secret store "host" "{\"auths\":{\"registry.example.test\":{\"username\":\"host\",\"password\":\"p\"}}}")
    (create-pull-secret store "team" "{\"auths\":{\"registry.example.test/team\":{\"username\":\"team\",\"password\":\"p\"}}}")
    (create-pull-secret store "copy" "{\"auths\":{\"registry.example.test\":{\"username\":\"host\",\"password\":\"p\"}}}")
    (is (equal '(("team" . "p") ("host" . "p"))
               (lookup "registry.example.test/team/a" "host" "team" "copy")))))

(test node-registry-credentials-backstop-pod-pull-secrets
  (uiop:with-temporary-file (:pathname file :stream stream :keep nil)
    (write-string
     "{\"auths\":{\"registry.example.test\":{\"username\":\"node\",\"password\":\"node-pass\"},\"registry.example.test/team\":{\"username\":\"team-node\",\"password\":\"team-pass\"}}}"
     stream)
    (finish-output stream)
    (with-temporary-store (store directory)
      (create-pull-secret store "pod"
                          "{\"auths\":{\"registry.example.test/team\":{\"username\":\"pod\",\"password\":\"pod-pass\"}}}")
      (let ((runtime (gr8s::make-containerd-runtime
                      :log-root (merge-pathnames "logs/" directory)
                      :registry-credentials (gr8s::load-node-registry-credentials file))))
        (setf (gr8s::containerd-runtime-resource-store runtime) store)
        (is (equal '(("pod" . "pod-pass") ("team-node" . "team-pass") ("node" . "node-pass"))
                   (gr8s::pod-image-pull-credentials
                    runtime (pull-secret-test-pod "pod") "c" "registry.example.test/team/a:1"))
            "Pod credentials are attempted before node credentials")
        (is (equal '(("node" . "node-pass"))
                   (gr8s::pod-image-pull-credentials
                    runtime (pull-secret-test-pod) "c" "registry.example.test/other/a:1")))))))

(test executable-credential-providers-match-invoke-cache-and-follow-static-credentials
  (let* ((directory
           (uiop:ensure-directory-pathname
            (sb-posix:mkdtemp
             (namestring (merge-pathnames "gr8s-credential-provider-XXXXXX"
                                           (uiop:temporary-directory))))))
         (plugin (merge-pathnames "test-provider" directory))
         (calls (merge-pathnames "calls" directory))
         (config (merge-pathnames "config.yaml" directory)))
    (unwind-protect
         (progn
           (with-open-file (out plugin :direction :output :if-exists :supersede)
             (format out "#!/bin/sh~%")
             (format out "request=$(cat)~%")
             (format out "case \"$request\" in *'\"image\":\"registry.example.test/team/a:1\"'*) ;; *) exit 2;; esac~%")
             (format out "[ \"$1\" = expected ] && [ \"$PLUGIN_ENV\" = yes ] || exit 3~%")
             (format out "printf x >> ~S~%" (namestring calls))
             (format out "printf '%s\\n' '{\"kind\":\"CredentialProviderResponse\",\"apiVersion\":\"credentialprovider.kubelet.k8s.io/v1\",\"cacheKeyType\":\"Registry\",\"cacheDuration\":\"1m\",\"auth\":{\"registry.example.test/team\":{\"username\":\"plugin\",\"password\":\"secret\"}}}'~%"))
           (sb-posix:chmod (namestring plugin) #o700)
           (with-open-file (out config :direction :output :if-exists :supersede)
             (format out
                     "apiVersion: kubelet.config.k8s.io/v1~%kind: CredentialProviderConfig~%providers:~%- name: test-provider~%  matchImages:~%  - registry.example.test/team~%  defaultCacheDuration: 30s~%  apiVersion: credentialprovider.kubelet.k8s.io/v1~%  args: [expected]~%  env:~%  - name: PLUGIN_ENV~%    value: \"yes\"~%"))
           (let ((providers (gr8s::load-image-credential-providers config directory)))
             (is (null (gr8s::image-credential-provider-entries
                        providers "other.example.test/team/a:1")))
             (is (equal '(("registry.example.test/team" "plugin" . "secret"))
                        (gr8s::image-credential-provider-entries
                         providers "registry.example.test/team/a:1")))
             (is (equal '(("registry.example.test/team" "plugin" . "secret"))
                        (gr8s::image-credential-provider-entries
                         providers "registry.example.test/team/a:1")))
             (is (= 1 (length (uiop:read-file-string calls))))
             (let ((runtime
                     (gr8s::make-containerd-runtime
                      :log-root directory
                      :registry-credentials
                      '(("registry.example.test/team" "static" . "password"))
                      :credential-providers providers)))
               (is (equal '(("static" . "password") ("plugin" . "secret"))
                          (gr8s::pod-image-pull-credentials
                           runtime (pull-secret-test-pod) "c"
                           "registry.example.test/team/a:1"))))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test credential-provider-registry-cache-is-isolated-by-registry
  (let ((provider
          (gr8s::make-image-credential-provider
           :name "provider" :match-images '("*.example.test")
           :cache (make-hash-table :test #'equal)))
        (calls nil))
    (with-replaced-functions
        ((gr8s::credential-provider-response-entries
           (lambda (provider image)
             (declare (ignore provider))
             (push image calls)
             (values (list (list* (gr8s::image-repository image) image "password"))
                     "Registry" 60))))
      (gr8s::image-credential-provider-entries (list provider) "one.example.test/a:1")
      (gr8s::image-credential-provider-entries (list provider) "one.example.test/b:1")
      (gr8s::image-credential-provider-entries (list provider) "two.example.test/a:1"))
    (is (equal '("two.example.test/a:1" "one.example.test/a:1") calls))))

(test failing-credential-provider-does-not-hide-earlier-credentials
  (let* ((provider
           (gr8s::make-image-credential-provider
            :name "broken" :match-images '("registry.example.test")))
         (runtime
           (gr8s::make-containerd-runtime
            :log-root "/nonexistent/"
            :registry-credentials
            '(("registry.example.test" "static" . "password"))
            :credential-providers (list provider))))
    (with-replaced-functions
        ((gr8s::credential-provider-response-entries
           (lambda (&rest arguments)
             (declare (ignore arguments))
             (error "plugin is unavailable"))))
      (is (equal '(("static" . "password"))
                 (gr8s::pod-image-pull-credentials
                  runtime (pull-secret-test-pod) "c" "registry.example.test/a:1"))))))

(test credential-provider-caches-an-empty-response
  (let ((provider
          (gr8s::make-image-credential-provider
           :name "empty" :match-images '("registry.example.test")))
        (calls 0))
    (with-replaced-functions
        ((gr8s::credential-provider-response-entries
           (lambda (&rest arguments)
             (declare (ignore arguments))
             (incf calls)
             (values nil "Global" 60))))
      (gr8s::image-credential-provider-entries (list provider) "registry.example.test/a:1")
      (gr8s::image-credential-provider-entries (list provider) "registry.example.test/b:1"))
    (is (= 1 calls))))

(test service-account-token-credential-provider-config-is-validated-and-loaded
  (uiop:with-temporary-file (:pathname config :stream out :keep nil)
    (format out
            "apiVersion: kubelet.config.k8s.io/v1~%kind: CredentialProviderConfig~%providers:~%- name: env~%  matchImages: [registry.example.test]~%  defaultCacheDuration: 30s~%  apiVersion: credentialprovider.kubelet.k8s.io/v1~%  tokenAttributes:~%    serviceAccountTokenAudience: registry.example.test~%    cacheType: ServiceAccount~%    requireServiceAccount: true~%    requiredServiceAccountAnnotationKeys: [registry.example.test/tenant]~%    optionalServiceAccountAnnotationKeys: [registry.example.test/region]~%")
    (finish-output out)
    (let* ((provider (first (gr8s::load-image-credential-providers config #p"/usr/bin/")))
           (attributes (gr8s::image-credential-provider-token-attributes provider)))
      (is (equal "registry.example.test" (getf attributes :audience)))
      (is (equal "ServiceAccount" (getf attributes :cache-type)))
      (is (getf attributes :require-service-account))
      (is (equal '("registry.example.test/tenant") (getf attributes :required-annotations)))
      (is (equal '("registry.example.test/region") (getf attributes :optional-annotations))))))

(test credential-provider-receives-bound-token-and-service-account-annotations
  (let* ((directory
           (uiop:ensure-directory-pathname
            (sb-posix:mkdtemp
             (namestring (merge-pathnames "gr8s-token-provider-XXXXXX"
                                           (uiop:temporary-directory))))))
         (plugin (merge-pathnames "token-provider" directory))
         (calls (merge-pathnames "calls" directory))
         (provider
           (gr8s::make-image-credential-provider
            :name "token-provider" :executable (namestring plugin)
            :api-version "credentialprovider.kubelet.k8s.io/v1"
            :match-images '("registry.example.test") :default-cache-seconds 60
            :token-attributes
            '(:audience "registry.example.test" :cache-type "ServiceAccount"
              :require-service-account t :required-annotations ("tenant.example/id")
              :optional-annotations ("tenant.example/region"))))
         (pod (pull-secret-test-pod))
         (requests nil))
    (setf (gethash "serviceAccountName" (gethash "spec" (pod-to-object pod))) "builder")
    (unwind-protect
         (progn
           (with-open-file (out plugin :direction :output :if-exists :supersede)
             (format out "#!/bin/sh~%")
             (format out "request=$(cat)~%")
             (format out "printf '%s' \"$request\" >> ~S~%" (namestring calls))
             (format out "case \"$request\" in *'\"serviceAccountToken\":\"bound-token\"'*'\"tenant.example/id\":\"acme\"'*) ;; *) exit 2;; esac~%")
             (format out "printf '%s\\n' '{\"kind\":\"CredentialProviderResponse\",\"apiVersion\":\"credentialprovider.kubelet.k8s.io/v1\",\"cacheKeyType\":\"Global\",\"cacheDuration\":\"1m\",\"auth\":{\"registry.example.test\":{\"username\":\"token-user\",\"password\":\"password\"}}}'~%"))
           (sb-posix:chmod (namestring plugin) #o700)
           (let ((runtime
                   (gr8s::make-containerd-runtime
                    :log-root directory :credential-providers (list provider)
                    :credential-provider-token-function
                    (lambda (requested-pod audience required optional)
                      (push (list requested-pod audience required optional) requests)
                      (values "bound-token"
                              (gr8s::core-object "tenant.example/id" "acme")
                              '(:namespace "sonobuoy" :name "builder" :uid "sa-uid"))))))
             (is (equal '(("token-user" . "password"))
                        (gr8s::pod-image-pull-credentials
                         runtime pod "c" "registry.example.test/team/a:1")))
             (is (= 1 (length requests)))
             (is (equal "registry.example.test" (second (first requests))))))
      (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))

(test malformed-node-registry-credential-files-fail-runtime-construction
  (uiop:with-temporary-file (:pathname file :stream stream :keep nil)
    (write-string "{\"auths\":7}" stream)
    (finish-output stream)
    (signals error
      (gr8s::load-node-registry-credentials file))))

(test missing-pull-secrets-are-skipped-and-reported
  (with-pull-credentials (lookup store)
    (create-pull-secret store "reg" "{\"auths\":{\"registry.example.test\":{\"username\":\"u\",\"password\":\"p\"}}}")
    (let ((events nil))
      (with-replaced-functions ((gr8s::record-container-lifecycle-event
                                 (lambda (runtime uid name occurrence reason message type)
                                   (declare (ignore runtime uid occurrence message))
                                   (push (list name reason type) events))))
        (is (equal '(("u" . "p")) (lookup "registry.example.test/a" "absent" "reg"))))
      (is (equal '(("c" "FailedToRetrieveImagePullSecret" "Warning")) events)))))

(test malformed-pull-secrets-fail-the-pull-without-quoting-the-secret
  (with-pull-credentials (lookup store)
    (create-pull-secret store "bad" (format nil "{\"auths\":{\"registry.example.test\":{\"auth\":~S}}}"
                                            (base64-text "no-colon-hunter2")))
    (let ((condition (handler-case (lookup "registry.example.test/a" "bad")
                       (gr8s::container-image-pull-error (condition) condition))))
      (is (typep condition 'gr8s::container-image-pull-error))
      (is (search "bad" (princ-to-string condition)))
      (is (null (search "hunter2" (princ-to-string condition)))))))

(defmacro with-recorded-pulls ((runtime attempts &optional (rejected ''())) &body body)
  "Run BODY with no image present and ATTEMPTS recording each pull's credential; REJECTED ones fail."
  `(let* ((,runtime (gr8s::make-containerd-runtime :log-root "/nonexistent/"))
          (,attempts nil) (gr8s::*container-lifecycle-clock* (let ((now 4000000000)) (lambda () now))))
     (with-replaced-functions ((gr8s::cri-image-present-p (constantly nil))
                               (gr8s::cri-pull-image (lambda (socket image &key auth timeout)
                                                       (declare (ignore socket image timeout))
                                                       (push auth ,attempts)
                                                       (when (member auth ,rejected :test #'equal)
                                                         (error "denied ~A" (car auth)))
                                                       "sha256:done")))
       ,@body)))

(defun wait-for-credentialed-pull (runtime image credentials)
  (gap-wait-for-pull runtime (gr8s::image-pull-job-key image credentials)))

(test pulls-try-each-credential-until-one-works
  (let ((old '("old" . "p")) (new '("new" . "p")))
    (with-recorded-pulls (runtime attempts (list old))
      (signals gr8s::container-image-pending
        (gr8s::ensure-container-image runtime "a:1" "IfNotPresent" (lambda () (list old new))))
      (wait-for-credentialed-pull runtime "a:1" (list old new))
      (is (equal (list new old) attempts))
      (is (gr8s::ensure-container-image runtime "a:1" "IfNotPresent" (lambda () (list old new)))))))

(test pulls-report-every-failure-when-no-credential-works
  (let ((one '("one" . "hunter2")) (two '("two" . "hunter3")))
    (with-recorded-pulls (runtime attempts (list one two))
      (signals gr8s::container-image-pending
        (gr8s::ensure-container-image runtime "a:1" "IfNotPresent" (lambda () (list one two))))
      (wait-for-credentialed-pull runtime "a:1" (list one two))
      (let ((text (handler-case (gr8s::ensure-container-image runtime "a:1" "IfNotPresent" (lambda () (list one two)))
                    (gr8s::container-image-pull-error (condition) (princ-to-string condition)))))
        (is (search "denied one" text))
        (is (search "denied two" text))
        (is (null (search "hunter" text)))))))

(test one-credentials-pull-never-serves-another
  (let ((good '("good" . "p")) (bad '("bad" . "p")))
    (with-recorded-pulls (runtime attempts (list bad))
      (flet ((ensure (&rest credentials)
               (gr8s::ensure-container-image runtime "a:1" "Always" (lambda () credentials))))
        (signals gr8s::container-image-pending (ensure good))
        (wait-for-credentialed-pull runtime "a:1" (list good))
        (is (ensure good) "a fresh pull satisfies its own credentials")
        ;; Neither an anonymous Pod nor a Pod holding other credentials shares it.
        (signals gr8s::container-image-pending (ensure))
        (wait-for-credentialed-pull runtime "a:1" nil)
        (signals gr8s::container-image-pending (ensure bad))
        (wait-for-credentialed-pull runtime "a:1" (list bad))
        (signals gr8s::container-image-pull-error (ensure bad))
        (is (ensure good) "another Pod's failure doesn't hold up working credentials")
        (is (equal (list bad nil good) attempts))))))

(test pull-requests-carry-the-credential-on-the-wire
  (let ((requests nil))
    (with-replaced-functions ((gr8s::make-unix-grpc-channel (constantly :channel))
                              (ag-grpc:channel-close (constantly nil))
                              (gr8s.cri.v1::make-image-service-stub (constantly :stub))
                              (gr8s.cri.v1::image-service-pull-image
                               (lambda (stub request &key timeout)
                                 (declare (ignore stub timeout))
                                 (push (ag-proto:deserialize-from-bytes
                                        'gr8s.cri.v1::pull-image-request (ag-proto:serialize-to-bytes request))
                                       requests)
                                 (error "stop before the status check"))))
      (signals error (gr8s::cri-pull-image "/nonexistent" "a:1" :auth '("user" . "secret")))
      (signals error (gr8s::cri-pull-image "/nonexistent" "a:1")))
    (let ((anonymous (first requests)) (private (second requests)))
      (is (equal "a:1" (gr8s.cri.v1::image (gr8s.cri.v1::image private))))
      (is (equal "user" (gr8s.cri.v1::username (gr8s.cri.v1::auth private))))
      (is (equal "secret" (gr8s.cri.v1::password (gr8s.cri.v1::auth private))))
      (is (equal "" (gr8s.cri.v1::server-address (gr8s.cri.v1::auth private)))
          "containerd rejects a server address that differs from the host it pulls from")
      (is (null (gr8s.cri.v1::auth anonymous))))))

(test credentials-are-not-fetched-when-no-pull-is-needed
  (let ((runtime (gr8s::make-containerd-runtime :log-root "/nonexistent/")))
    (with-replaced-functions ((gr8s::cri-image-present-p (constantly t)))
      (is (gr8s::ensure-container-image runtime "a:1" "IfNotPresent"
                                        (lambda () (error "a malformed Secret must not block a present image")))))))

(test pods-validate-image-pull-secrets
  (dolist (field '("7" "[7]" "[{\"name\":7}]" "[{\"name\":\"Not_Valid\"}]" "[{\"name\":\"a\",\"other\":1}]"))
    (signals kubernetes-error
      (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p\"},\"spec\":{\"imagePullSecrets\":~A,\"containers\":[{\"name\":\"c\",\"image\":\"b\"}]}}" field))))
  (dolist (field '("null" "[]" "[{\"name\":\"\"}]" "[{\"name\":\"reg\"}]"))
    (is (not (null (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p\"},\"spec\":{\"imagePullSecrets\":~A,\"containers\":[{\"name\":\"c\",\"image\":\"b\"}]}}" field)))))))

(test pull-secrets-reach-the-node-and-a-missing-one-delays-nothing
  (with-temporary-store (store directory)
    (create-pull-secret store "reg" "{\"auths\":{}}")
    (let ((pod (pull-secret-test-pod "reg" "absent" "")))
      (is (member '("secrets" "reg" t) (gr8s::pod-resource-reference-declarations pod) :test #'equal))
      (is (notany (lambda (reference) (equal "" (second reference)))
                  (gr8s::pod-resource-reference-declarations pod)))
      (is (equal '("reg")
                 (mapcar (lambda (object) (gethash "name" (gethash "metadata" object)))
                         (gr8s::pod-referenced-resource-objects store pod)))))))

(test pods-inherit-their-accounts-pull-secrets-only-when-naming-none
  (with-temporary-store (store directory)
    (setf (gr8s::pod-store-in-cluster-config store) (list :host "10.96.0.1" :port 443 :ca-pem "test-ca"))
    (gr8s::create-core-resource store "serviceaccounts"
      (gr8s::core-object "metadata" (gr8s::core-object "name" "default")
                         "imagePullSecrets" (vector (gr8s::core-object "name" "from-account")))
      "sonobuoy")
    (flet ((admitted-secrets (&rest names)
             (map 'list (lambda (reference) (gethash "name" reference))
                  (gethash "imagePullSecrets"
                           (gethash "spec" (pod-to-object
                                            (gr8s::admit-in-cluster-pod store (apply #'pull-secret-test-pod names))))))))
      (is (equal '("from-account") (admitted-secrets)))
      (is (equal '("own") (admitted-secrets "own"))))))
