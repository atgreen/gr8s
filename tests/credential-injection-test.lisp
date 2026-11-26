;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Prove credential injection's model and control plane (podster-wv1w.3): the
;;;; SecurityProfile subset gr8s accepts and refuses, which rule matches a request,
;;;; how a credential is found and rendered, which Pods a profile selects and which
;;;; Secrets their assignments may carry, and the egress CA and its trust bundle.

(in-package #:gr8s/tests)
(def-suite credential-injection :in gr8s)
(in-suite credential-injection)

(defparameter +ci-profile-json+
  "{\"apiVersion\":\"agents.kruise.io/v1alpha1\",\"kind\":\"SecurityProfile\",
    \"metadata\":{\"name\":\"claude-anthropic\",\"namespace\":\"gr8\"},
    \"spec\":{\"selector\":{\"matchLabels\":{\"gr8s.io/gr8-command\":\"claude\"}},
      \"rules\":[{\"name\":\"anthropic-api-key\",
        \"match\":[{\"domains\":[\"api.anthropic.com\"],\"schemes\":[\"https\"],
                    \"paths\":[{\"type\":\"Prefix\",\"value\":\"/v1/\"}],\"methods\":[\"POST\",\"GET\"]}],
        \"actions\":{\"tokenTransformation\":{\"type\":\"ApiKey\",\"failStrategy\":\"Block\",
          \"credentialRef\":{\"secret\":{\"name\":\"anthropic\"}},
          \"apiKey\":{\"targetHeaders\":{\"names\":[\"x-api-key\"]},\"value\":{\"template\":\"{{ .Token }}\"}}}}}]}}")

(defun ci-normalize (json)
  (gr8s.resources::normalize-core-resource "securityprofiles" (com.inuoe.jzon:parse json) "gr8" nil nil))

(test ci-security-profile-accepts-the-subset-gr8s-implements
  (let ((object (ci-normalize +ci-profile-json+)))
    (is (equal "SecurityProfile" (gethash "kind" object)))
    (is (equal "agents.kruise.io/v1alpha1" (gethash "apiVersion" object))))
  (flet ((variant (from to)
           (let ((text (cl-ppcre:regex-replace (cl-ppcre:quote-meta-chars from) +ci-profile-json+ to)))
             (assert (string/= text +ci-profile-json+) () "fixture does not contain ~S" from)
             text)))
    (dolist (bad (list (variant "\"type\":\"ApiKey\"" "\"type\":\"OAuth\"")
                       (variant "\"failStrategy\":\"Block\"" "\"failStrategy\":\"Allow\"")
                       (variant "{{ .Token }}" "{{ .Header.foo }}")
                       (variant "{{ .Token }}" "static")
                       (variant "\"api.anthropic.com\"" "\"not a host\"")
                       (variant "\"schemes\":[\"https\"]" "\"schemes\":[\"ftp\"]")
                       (variant "\"value\":\"/v1/\"" "\"value\":\"v1\"")
                       (variant "\"names\":[\"x-api-key\"]" "\"names\":[\"bad header\"]")
                       (variant "\"tokenTransformation\"" "\"headerManipulation\"")
                       (variant "\"credentialRef\":{\"secret\":{\"name\":\"anthropic\"}}"
                                "\"credentialRef\":{\"credentialProvider\":{\"name\":\"vault\"}}")))
      (signals gr8s.resources::kubernetes-error (ci-normalize bad)))))

(defun ci-rules ()
  (let ((profiles (gr8s.network::security-profile-specs-from-objects
                   (list (com.inuoe.jzon:parse +ci-profile-json+)))))
    (values (gr8s.network::pod-injection-rules
             (gr8s.network::make-np-pod :name "agent" :namespace "gr8"
                                        :labels (gr8s.network::np-labels "gr8s.io/gr8-command" "claude"))
             profiles)
            profiles)))

(test ci-a-rule-matches-by-host-scheme-method-and-path
  (let ((rules (ci-rules)))
    (is (= 1 (length rules)))
    (is-true (gr8s.network::injection-host-p rules "api.anthropic.com"))
    (is-false (gr8s.network::injection-host-p rules "platform.claude.com"))
    (flet ((match (scheme method path)
             (gr8s.network::matching-injection-rule rules "api.anthropic.com" scheme method path)))
      (is (not (null (match "https" "post" "/v1/messages?beta=true"))))
      (is (null (match "http" "POST" "/v1/messages")))
      (is (null (match "https" "DELETE" "/v1/messages")))
      (is (null (match "https" "POST" "/v2/messages"))))))

(test ci-a-profile-selects-pods-in-its-namespace-by-label
  (multiple-value-bind (rules profiles) (ci-rules)
    (declare (ignore rules))
    (is (equal '("anthropic") (gr8s.network::security-profile-secret-names
                               profiles "gr8" (gr8s.network::np-labels "gr8s.io/gr8-command" "claude"))))
    (is (null (gr8s.network::security-profile-secret-names
               profiles "prod" (gr8s.network::np-labels "gr8s.io/gr8-command" "claude"))))
    (is (null (gr8s.network::security-profile-secret-names
               profiles "gr8" (gr8s.network::np-labels "gr8s.io/gr8-command" "ping"))))))

(test ci-the-credential-comes-from-the-secret-and-renders-into-the-template
  (let ((one (com.inuoe.jzon:parse "{\"data\":{\"apiKey\":\"c2stYW50LXJlYWw=\"}}"))
        (two (com.inuoe.jzon:parse "{\"data\":{\"a\":\"eA==\",\"b\":\"eQ==\"}}")))
    (is (equal "sk-ant-real" (gr8s.network::secret-credential one nil)))
    (is (equal "y" (gr8s.network::secret-credential two "b")))
    ;; Two keys and none named: no single answer, so no credential.
    (is (null (gr8s.network::secret-credential two nil)))
    (is (null (gr8s.network::secret-credential two "c"))))
  (is (equal "Bearer sk-1" (gr8s.network::render-injection-value "Bearer {{ .Token }}" "sk-1")))
  (is (equal "sk-$1\\x" (gr8s.network::render-injection-value "{{.Token}}" "sk-$1\\x"))))

(test ci-the-control-plane-creates-the-egress-ca-and-its-trust-bundle
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "namespaces"
                                          (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "kube-system")) nil)
    (gr8s.controllers::ensure-egress-ca store)
    (let ((secret (gr8s.resources::get-core-resource store "secrets" "kube-system" "gr8s-egress-ca"))
          (bundle (gr8s.resources::get-core-resource store "clustertrustbundles" nil "gr8s-egress")))
      (is (equal "kubernetes.io/tls" (gethash "type" secret)))
      (is (search "BEGIN CERTIFICATE" (gethash "trustBundle" (gethash "spec" bundle))))
      ;; The node can sign leaves with it.
      (multiple-value-bind (key certificate) (gr8s.controllers::egress-ca-material store)
        (let ((chain (funcall (gr8s.controllers::make-egress-leaf-minter key certificate) "api.anthropic.com")))
          (is (member "api.anthropic.com" (pure-tls::certificate-dns-names (first chain)) :test #'equal))))
      ;; Idempotent: a second pass keeps the same CA.
      (gr8s.controllers::ensure-egress-ca store)
      (is (equalp (gethash "data" secret)
                  (gethash "data" (gr8s.resources::get-core-resource store "secrets" "kube-system" "gr8s-egress-ca")))))))

(test ci-only-a-selected-pods-assignment-carries-the-profiles-secret
  (with-temporary-store (store path)
    (values path)
    (gr8s.resources::create-core-resource store "namespaces"
                                          (gr8s.resources::core-object "metadata" (gr8s.resources::core-object "name" "gr8")) nil)
    (gr8s.resources::create-core-resource
     store "secrets" (com.inuoe.jzon:parse "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"anthropic\",\"namespace\":\"gr8\"},
                                             \"data\":{\"apiKey\":\"c2stYW50LXJlYWw=\"}}")
     "gr8")
    (gr8s.resources::create-core-resource store "securityprofiles" (com.inuoe.jzon:parse +ci-profile-json+) "gr8")
    (flet ((pod (name command)
             (create-pod store (parse-pod (format nil "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",
                 \"metadata\":{\"name\":\"~A\",\"namespace\":\"gr8\",\"labels\":{\"gr8s.io/gr8-command\":\"~A\"}},
                 \"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"busybox\"}]}}" name command)))))
      (let ((claude (pod "claude-1" "claude")) (ping (pod "ping-1" "ping")))
        (flet ((secret-names (pod)
                 (loop for object in (gr8s.kubelet::pod-referenced-resource-objects store pod)
                       when (equal "Secret" (gethash "kind" object))
                         collect (gethash "name" (gethash "metadata" object)))))
          (is (equal '("anthropic") (secret-names claude)))
          (is (null (secret-names ping))))
        ;; The node accepts it for the selected Pod only.
        (let ((gr8s.kubelet::*assignment-security-profiles*
                (gr8s.network::security-profile-specs-from-objects
                 (list (com.inuoe.jzon:parse +ci-profile-json+)))))
          (is (equal '("anthropic") (gr8s.kubelet::pod-security-profile-secret-names
                                     gr8s.kubelet::*assignment-security-profiles* claude)))
          (is (null (gr8s.kubelet::pod-security-profile-secret-names
                     gr8s.kubelet::*assignment-security-profiles* ping))))))))

(test ci-sandbox-profiles-grant-only-paths-under-home
  (flet ((normalize (spec)
           (gr8s.resources::normalize-core-resource
            "sandboxprofiles"
            (com.inuoe.jzon:parse (format nil "{\"apiVersion\":\"gr8.gr8s.io/v1alpha1\",\"kind\":\"SandboxProfile\",
                                                \"metadata\":{\"name\":\"claude\"},\"spec\":~A}" spec))
            nil "claude" nil)))
    (is (equal "SandboxProfile"
               (gethash "kind" (normalize "{\"commands\":[\"claude\"],
                  \"home\":{\"readWrite\":[\".claude\",\".claude.json\"],\"readOnly\":[\".gitconfig\",\".config/git\"]},
                  \"env\":{\"ANTHROPIC_API_KEY\":\"gr8s-injected\"}}"))))
    (dolist (bad '("{\"commands\":[]}"
                   "{\"commands\":[\"/usr/bin/claude\"]}"
                   "{\"commands\":[\"claude\"],\"home\":{\"readWrite\":[\"/etc\"]}}"
                   "{\"commands\":[\"claude\"],\"home\":{\"readOnly\":[\"../other\"]}}"
                   "{\"commands\":[\"claude\"],\"home\":{\"readOnly\":[\".ssh/../../x\"]}}"
                   "{\"commands\":[\"claude\"],\"env\":{\"BAD-NAME\":\"x\"}}"
                   "{\"commands\":[\"claude\"],\"mounts\":[]}"))
      (signals gr8s.resources::kubernetes-error (normalize bad)))))

(test ci-sandbox-profiles-may-name-placeholder-credential-files
  (is (equal "SandboxProfile"
             (gethash "kind" (gr8s.resources::normalize-core-resource
                              "sandboxprofiles"
                              (com.inuoe.jzon:parse "{\"apiVersion\":\"gr8.gr8s.io/v1alpha1\",\"kind\":\"SandboxProfile\",
                                 \"metadata\":{\"name\":\"claude\"},
                                 \"spec\":{\"commands\":[\"claude\"],\"home\":{\"placeholders\":[\".claude/.credentials.json\"]}}}")
                              nil "claude" nil))))
  (signals gr8s.resources::kubernetes-error
    (gr8s.resources::normalize-core-resource
     "sandboxprofiles"
     (com.inuoe.jzon:parse "{\"apiVersion\":\"gr8.gr8s.io/v1alpha1\",\"kind\":\"SandboxProfile\",
        \"metadata\":{\"name\":\"claude\"},\"spec\":{\"commands\":[\"claude\"],\"home\":{\"placeholders\":[\"/etc/shadow\"]}}}")
     nil "claude" nil)))

(defparameter +ci-login-security-profile+ "{\"apiVersion\":\"agents.kruise.io/v1alpha1\",\"kind\":\"SecurityProfile\",\"metadata\":{\"name\":\"claude-oauth\",\"namespace\":\"gr8\"},\"spec\":{\"rules\":[{\"actions\":{\"tokenTransformation\":{\"apiKey\":{\"targetHeaders\":{\"names\":[\"authorization\"]},\"value\":{\"template\":\"Bearer {{ .Token }}\"}},\"credentialRef\":{\"secret\":{\"key\":\"accessToken\",\"name\":\"claude-oauth\"}},\"failStrategy\":\"Block\",\"type\":\"ApiKey\"}},\"match\":[{\"domains\":[\"api.anthropic.com\"],\"schemes\":[\"https\"]}],\"name\":\"anthropic-oauth\"}],\"selector\":{\"matchLabels\":{\"gr8s.io/gr8-command\":\"claude\"}}}}")
(defparameter +ci-login-sandbox-profile+ "{\"apiVersion\":\"gr8.gr8s.io/v1alpha1\",\"kind\":\"SandboxProfile\",\"metadata\":{\"name\":\"claude\"},\"spec\":{\"commands\":[\"claude\"],\"home\":{\"placeholders\":[\".claude/.credentials.json\"],\"readWrite\":[\".claude\",\".claude.json\"]}}}")

(test ci-the-objects-gr8-login-applies-are-valid
  ;; Emitted by gr8's TestEmitLoginProfiles (gr8/internal/client/login.go).
  (is (equal "SecurityProfile"
             (gethash "kind" (gr8s.resources::normalize-core-resource
                              "securityprofiles" (com.inuoe.jzon:parse +ci-login-security-profile+) "gr8" nil nil))))
  (is (equal "SandboxProfile"
             (gethash "kind" (gr8s.resources::normalize-core-resource
                              "sandboxprofiles" (com.inuoe.jzon:parse +ci-login-sandbox-profile+) nil "claude" nil))))
  ;; The bearer template renders the token the Secret's accessToken holds.
  (let ((rule (first (gr8s.network::security-profile-spec-rules
                      (first (gr8s.network::security-profile-specs-from-objects
                              (list (com.inuoe.jzon:parse +ci-login-security-profile+))))))))
    (is (equal "accessToken" (gr8s.network::injection-rule-secret-key rule)))
    (is (equal "Bearer t" (gr8s.network::render-injection-value (gr8s.network::injection-rule-template rule) "t")))))
