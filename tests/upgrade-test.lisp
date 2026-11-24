;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Verify `gr8s upgrade's parts: release versions and their order, release
;;;; signatures, the release artifact through a registry that demands a token, and
;;;; the commands that install a package.

(in-package #:gr8s/tests)
(def-suite upgrade :in gr8s)
(in-suite upgrade)

(test release-versions-order-by-their-numbers
  (is (eql -1 (gr8s.upgrade:compare-gr8s-versions "v1.37.2-gr8s.7" "v1.37.2-gr8s.10")))
  (is (eql 0 (gr8s.upgrade:compare-gr8s-versions "v1.37.2-gr8s.7" "v1.37.2-gr8s.7")))
  (is (eql 1 (gr8s.upgrade:compare-gr8s-versions "v1.38.0-gr8s.1" "v1.37.2-gr8s.9")))
  ;; A build between releases, and an agent too old to say, have no place in the order.
  (is (null (gr8s.upgrade:compare-gr8s-versions "v1.37.2-g1a2b3c4" "v1.37.2-gr8s.7")))
  (is (null (gr8s.upgrade:compare-gr8s-versions "v1.37.2-gr8s.6+dirty" "v1.37.2-gr8s.7")))
  (is (null (gr8s.upgrade:parse-gr8s-version "gr8s"))))

(defun test-release-key ()
  (gr8s.upgrade:read-release-signing-key (ironclad:byte-array-to-hex-string (ironclad:random-data 32))))

(test release-manifests-are-trusted-only-under-a-trusted-key
  (let ((key (test-release-key)) (other (test-release-key))
        (octets (trivial-utf-8:string-to-utf-8-bytes "{\"version\":\"v1.0.0-gr8s.1\"}")))
    (let ((signature (gr8s.upgrade::sign-release-manifest key octets)))
      (is (eq key (gr8s.upgrade::verify-release-manifest octets signature (gr8s.upgrade:release-key-id key) :keys (list key))))
      (signals gr8s.upgrade:upgrade-error
        (gr8s.upgrade::verify-release-manifest octets signature (gr8s.upgrade:release-key-id key) :keys (list other)))
      (let ((tampered (copy-seq octets)))
        (setf (aref tampered 3) (char-code #\V))
        (signals gr8s.upgrade:upgrade-error
          (gr8s.upgrade::verify-release-manifest tampered signature (gr8s.upgrade:release-key-id key) :keys (list key)))))
    ;; A key with no private half can't sign.
    (signals gr8s.upgrade:upgrade-error
      (gr8s.upgrade::sign-release-manifest (first gr8s.upgrade::*trusted-release-keys*) octets))))

(test the-release-key-gr8s-carries-is-well-formed
  (is (= 1 (length gr8s.upgrade::*trusted-release-keys*)))
  (is (= 32 (length (gr8s.upgrade::release-key-public (first gr8s.upgrade::*trusted-release-keys*))))))

(test artifact-references-name-a-registry-repository-and-tag-or-digest
  (is (equal '("ghcr.io" "atgreen/gr8s-packages" "v1.37.2-gr8s.8")
             (multiple-value-list (gr8s.upgrade:parse-artifact-reference "ghcr.io/atgreen/gr8s-packages:v1.37.2-gr8s.8"))))
  (is (equal "registry.lab:30500"
             (gr8s.upgrade:parse-artifact-reference "registry.lab:30500/gr8s/packages:v1")))
  (let ((digest (format nil "sha256:~64,,,'0A" "")))
    (is (equal digest (nth-value 2 (gr8s.upgrade:parse-artifact-reference
                                    (format nil "ghcr.io/atgreen/gr8s-packages@~A" digest))))))
  (dolist (bad '("gr8s-packages:v1" "ghcr.io/atgreen/gr8s-packages" "ghcr.io/Atgreen/x:v1"
                 "ghcr.io/atgreen/x@sha256:short" "ghcr.io/atgreen/x:v1;rm"))
    (signals gr8s.upgrade:upgrade-error (gr8s.upgrade:parse-artifact-reference bad))))

(defun fake-registry-answer (objects uploads uri method content)
  "How the fake registry answers METHOD on URI: (values status body headers)."
  (multiple-value-bind (match groups) (cl-ppcre:scan-to-strings "^/v2/(.+)/(manifests|blobs)/(.*)$" (puri:uri-path uri))
    (if (not match)
        (values 404 #() nil)
        (let ((repository (aref groups 0)) (kind (aref groups 1)) (reference (aref groups 2)))
          (cond
            ((and (equal kind "blobs") (equal reference "uploads/") (eq method :post))
             (values 202 #() (list (cons :location (format nil "/v2/~A/blobs/uploads/~D" repository (funcall uploads))))))
            ((and (equal kind "blobs") (uiop:string-prefix-p "uploads/" reference) (eq method :put))
             (setf (gethash (list repository (hunchentoot:url-decode (subseq (puri:uri-query uri) 7))) objects) content)
             (values 201 #() nil))
            ((member method '(:get :head))
             (let ((object (gethash (list repository reference) objects)))
               (if object (values 200 (if (eq method :head) #() object) nil) (values 404 #() nil))))
            ((and (equal kind "manifests") (eq method :put))
             (setf (gethash (list repository reference) objects) content
                   (gethash (list repository (gr8s.upgrade::sha256-digest content)) objects) content)
             (values 201 #() nil))
            (t (values 405 #() nil)))))))

(defun fake-registry (&optional (token "t0k"))
  "A registry in memory, as REGISTRY-HTTP-REQUEST answers: it hands out TOKEN for any
request to its token realm and refuses every other request without it. Returns the
request function and the registry's objects, by (repository reference)."
  (let ((objects (make-hash-table :test #'equal)) (uploads 0))
    (values
     (lambda (url headers &key (method :get) content want-stream &allow-other-keys)
       (let ((uri (puri:parse-uri url))
             (authorization (cdr (assoc "Authorization" headers :test #'string-equal))))
         (multiple-value-bind (status body response-headers)
             (cond ((equal (puri:uri-host uri) "auth.example")
                    (values 200 (trivial-utf-8:string-to-utf-8-bytes (format nil "{\"token\":~S}" token)) nil))
                   ((not (equal authorization (format nil "Bearer ~A" token)))
                    (values 401 #() '((:www-authenticate . "Bearer realm=\"https://auth.example/token\",service=\"example\",scope=\"repository:r:pull\""))))
                   (t (fake-registry-answer objects (lambda () (incf uploads)) uri method content)))
           (values (if want-stream
                       (flexi-streams:make-in-memory-input-stream (coerce body '(vector (unsigned-byte 8))))
                       body)
                   status response-headers))))
     objects)))

(defun write-test-package (directory name contents)
  (let ((path (merge-pathnames name directory)))
    (with-open-file (out path :direction :output :element-type '(unsigned-byte 8) :if-exists :supersede)
      (write-sequence (trivial-utf-8:string-to-utf-8-bytes contents) out))
    path))

(test a-release-artifact-travels-signed-and-each-host-takes-its-package
  (uiop:with-temporary-file (:pathname scratch :keep nil)
    (let* ((directory (uiop:ensure-directory-pathname (format nil "~A.d" (namestring scratch))))
           (key (test-release-key)))
      (ensure-directories-exist directory)
      (multiple-value-bind (registry objects) (fake-registry)
        (let ((gr8s.upgrade::*registry-http* registry)
              (packages (list (write-test-package directory "gr8s-1.37.2+gr8s.9-1.x86_64.rpm" "an rpm")
                              (write-test-package directory "gr8s_1.37.2+gr8s.9-1_arm64.deb" "a deb")
                              (write-test-package directory "gr8s-linux-amd64" "an executable"))))
          (unwind-protect
               (let ((digest (gr8s.upgrade:publish-release-artifact
                              "registry.example/gr8s/packages:v1.37.2-gr8s.9" "v1.37.2-gr8s.9" packages key)))
                 (let ((artifact (gr8s.upgrade:fetch-release-artifact
                                  "registry.example/gr8s/packages:v1.37.2-gr8s.9" :keys (list key))))
                   (is (equal "v1.37.2-gr8s.9" (gr8s.upgrade:release-artifact-version artifact)))
                   (is (equal digest (gr8s.upgrade:release-artifact-digest artifact)))
                   (is (equal '(("rpm" "amd64") ("deb" "arm64") ("binary" "amd64"))
                              (mapcar (lambda (package) (list (getf package :format) (getf package :architecture)))
                                      (gr8s.upgrade:release-artifact-packages artifact)))))
                 ;; The same release by its digest; a host takes only its own package.
                 (let ((prepared (gr8s.upgrade:prepare-host-upgrade
                                  (format nil "registry.example/gr8s/packages@~A" digest)
                                  :keys (list key) :format "deb" :architecture "arm64"
                                  :directory (merge-pathnames "host/" directory))))
                   (is (equal "v1.37.2-gr8s.9" (getf prepared :version)))
                   (is (equal "a deb" (uiop:read-file-string (getf prepared :path)))))
                 (signals gr8s.upgrade:upgrade-error
                   (gr8s.upgrade:prepare-host-upgrade "registry.example/gr8s/packages:v1.37.2-gr8s.9"
                                                      :keys (list key) :format "rpm" :architecture "arm64"
                                                      :directory (merge-pathnames "host/" directory)))
                 ;; Another release key is no key at all.
                 (signals gr8s.upgrade:upgrade-error
                   (gr8s.upgrade:fetch-release-artifact "registry.example/gr8s/packages:v1.37.2-gr8s.9"
                                                        :keys (list (test-release-key))))
                 ;; A mirror holds the same manifest, so the same signature.
                 (let ((gr8s.upgrade::*trusted-release-keys* (list key)))
                   (is (equal digest (gr8s.upgrade:mirror-release-artifact
                                      "registry.example/gr8s/packages:v1.37.2-gr8s.9"
                                      "registry.example/mirror/gr8s:v1.37.2-gr8s.9"))))
                 (is (equal "v1.37.2-gr8s.9"
                            (gr8s.upgrade:release-artifact-version
                             (gr8s.upgrade:fetch-release-artifact "registry.example/mirror/gr8s:v1.37.2-gr8s.9" :keys (list key)))))
                 ;; A registry that changes a package's bytes is caught.
                 (let ((rpm (find "gr8s-1.37.2+gr8s.9-1.x86_64.rpm"
                                  (gr8s.upgrade:release-artifact-packages
                                   (gr8s.upgrade:fetch-release-artifact "registry.example/gr8s/packages:v1.37.2-gr8s.9" :keys (list key)))
                                  :key (lambda (package) (getf package :file)) :test #'equal)))
                   (setf (gethash (list "gr8s/packages" (getf rpm :digest)) objects)
                         (trivial-utf-8:string-to-utf-8-bytes "not an rpm"))
                   (signals gr8s.upgrade:upgrade-error
                     (gr8s.upgrade:prepare-host-upgrade "registry.example/gr8s/packages:v1.37.2-gr8s.9"
                                                        :keys (list key) :format "rpm" :architecture "amd64"
                                                        :directory (merge-pathnames "tampered/" directory)))))
            (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore)))))))

(test each-package-form-installs-its-own-way
  (flet ((command (format &optional unit)
           (gr8s.upgrade::install-command (list :format format :path "/var/lib/gr8s/upgrade/v1/it's")
                                          "/usr/bin/gr8s" unit)))
    (is (equal "rpm -U --oldpackage --replacepkgs '/var/lib/gr8s/upgrade/v1/it'\\''s'" (command "rpm")))
    (is (equal "dpkg -i '/var/lib/gr8s/upgrade/v1/it'\\''s'" (command "deb")))
    (is (search "&& mv -f '/usr/bin/gr8s.gr8s-new' '/usr/bin/gr8s' && systemctl restart 'gr8s-server.service'"
                (command "binary" "gr8s-server.service")))
    (is (not (search "systemctl" (command "binary"))))))

(defun lab-hosts (&key (gr8s2 "in-contact") (pfwit "in-contact") (local-ready t) (version "v1.37.2-gr8s.7"))
  "The lab: voters gr8s2 and gvision, which leads; the witness pfwit; the worker gr8s-local."
  (list (list :name "gvision" :role "voter" :leader t :contact "self" :ready t :version version)
        (list :name "gr8s2" :role "voter" :contact gr8s2 :ready t :version version)
        (list :name "pfwit" :role "witness" :contact pfwit :ready t)
        (list :name "gr8s-local" :ready local-ready :version version)))

(defun plan-summary (hosts &rest options)
  (multiple-value-bind (steps problems) (apply #'gr8s.upgrade:plan-cluster-upgrade hosts "v1.37.2-gr8s.8" options)
    (values (mapcar (lambda (step) (list* (getf step :host) (getf step :action)
                                          (and (getf step :transfer-to) (list (getf step :transfer-to)))))
                    steps)
            problems)))

(test a-healthy-cluster-upgrades-voters-one-at-a-time-and-the-leader-last
  (multiple-value-bind (steps problems) (plan-summary (lab-hosts))
    (is (equal '(("gr8s2" :upgrade) ("gvision" :upgrade "gr8s2") ("pfwit" :optional) ("gr8s-local" :upgrade)) steps))
    (is (null problems))))

(test an-upgrade-that-would-lose-quorum-is-refused
  ;; One voter down: upgrading the other would leave the witness voting alone.
  (multiple-value-bind (steps problems) (plan-summary (lab-hosts :gr8s2 "never-heard"))
    (is (equal '("gr8s2" :manual) (first steps)))
    (is (= 1 (length problems)))
    (is (search "upgrading gvision would leave 1 of 3 votes while it restarts, and quorum needs 2" (first problems))))
  ;; The witness down: each voter's restart leaves one vote.
  (is (= 2 (length (nth-value 1 (plan-summary (lab-hosts :pfwit "unknown"))))))
  ;; An operator can accept the outage.
  (is (null (nth-value 1 (plan-summary (lab-hosts :gr8s2 "never-heard") :allow-quorum-loss t)))))

(test a-worker-that-is-away-upgrades-when-it-returns
  (multiple-value-bind (steps problems) (plan-summary (lab-hosts :local-ready nil))
    (is (equal '("gr8s-local" :on-reconnect) (fourth steps)))
    (is (null problems))))

(test hosts-at-the-release-are-skipped-and-a-downgrade-is-a-rollback
  (is (equal '(:skip :skip :optional :skip)
             (mapcar #'second (plan-summary (lab-hosts :version "v1.37.2-gr8s.8")))))
  (multiple-value-bind (steps problems) (plan-summary (lab-hosts :version "v1.37.2-gr8s.9"))
    (declare (ignore steps))
    (is (= 3 (length problems)))
    (is (search "a downgrade is a rollback" (first problems))))
  (is (null (nth-value 1 (plan-summary (lab-hosts :version "v1.37.2-gr8s.9") :allow-downgrade t))))
  (signals gr8s.upgrade:upgrade-error (gr8s.upgrade:plan-cluster-upgrade (lab-hosts) "latest")))

;;; Versions in mixed clusters (podster-igs.6): during an upgrade some hosts run the
;;; old release and some the new, so each side must make sense of the other.

(test a-node-says-which-release-its-agent-runs-and-an-old-agent-says-none
  (let* ((node (gr8s.model::make-node-record :id "n1" :name "worker" :pod-cidr "10.88.1.0/24"))
         (old (gr8s.store::parse-node-record (gr8s.store::node-record-to-object node) :expire-leases nil)))
    ;; An agent too old to report shows no release, not the control plane's.
    (is (null (gr8s.model:node-record-agent-version old)))
    (is (equal "v0.0.0-unknown" (gethash "kubeletVersion" (gethash "nodeInfo" (gethash "status" (gr8s.resources::node-api-object old))))))
    (setf (gr8s.model:node-record-agent-version node) "v1.37.2-gr8s.8"
          (gr8s.model:node-record-agent-architecture node) "arm64")
    (let* ((reloaded (gr8s.store::parse-node-record (gr8s.store::node-record-to-object node) :expire-leases nil))
           (info (gethash "nodeInfo" (gethash "status" (gr8s.resources::node-api-object reloaded)))))
      (is (equal "v1.37.2-gr8s.8" (gethash "kubeletVersion" info)))
      (is (equal "arm64" (gethash "architecture" info))))))

(test an-agent-reports-only-what-it-knows-of-itself
  (with-temporary-store (store path)
    (declare (ignore path))
    (gr8s.controllers::register-node store (gr8s.model::make-node-record :id "n1" :name "worker" :pod-cidr "10.88.1.0/24"))
    ;; An older agent's hello says just "gr8s".
    (gr8s.controllers::update-node-agent-info store "worker" "gr8s" "")
    (is (null (gr8s.model:node-record-agent-version (gr8s.controllers::get-node store "worker"))))
    (gr8s.controllers::update-node-agent-info store "worker" "v1.37.2-gr8s.8" "amd64")
    (let ((node (gr8s.controllers::get-node store "worker")))
      (is (equal "v1.37.2-gr8s.8" (gr8s.model:node-record-agent-version node)))
      (is (equal "amd64" (gr8s.model:node-record-agent-architecture node))))))

(test an-agent-too-old-to-upgrade-remotely-is-told-how-to-upgrade
  (with-temporary-store (store path)
    (declare (ignore path))
    (let* ((server (gr8s.apiserver::%make-node-grpc-server :store store))
           (operation (gr8s.apiserver::make-pending-node-operation
                       "worker" (make-instance 'gr8s.node.v1::operation-request :operation-id "u1"))))
      (setf (gethash "u1" (gr8s.apiserver::node-grpc-server-operations server)) operation)
      ;; What an older agent answers an operation kind it doesn't know.
      (gr8s.apiserver::finish-node-operation operation :error "Unsupported node operation")
      (let ((condition (handler-case (progn (gr8s.apiserver::await-host-upgrade server "worker" operation "r.example/g:v1") nil)
                         (kubernetes-error (condition) condition))))
        (is (= 501 (gr8s.model:kubernetes-error-status-code condition)))
        (is (search "sudo gr8s upgrade self --to r.example/g:v1" (princ-to-string condition)))))))

(test a-node-away-during-an-upgrade-is-sent-it-when-it-returns
  (with-temporary-store (store path)
    (declare (ignore path))
    (flet ((record (phase state)
             (let ((upgrade (com.inuoe.jzon:parse
                             (format nil "{\"apiVersion\":\"upgrade.gr8s.io/v1\",\"kind\":\"ClusterUpgrade\",
                                          \"metadata\":{\"name\":\"v1.37.2-gr8s.8\"},
                                          \"spec\":{\"target\":\"v1.37.2-gr8s.8\",\"reference\":\"r.example/g@sha256:00\"},
                                          \"status\":{\"phase\":~S,\"hosts\":[{\"name\":\"edge\",\"node\":\"edge\",\"state\":~S}]}}"
                                     phase state))))
               (gr8s.store::with-store-lock (store)
                 (setf (gethash (list gr8s.apiserver::+cluster-upgrade-resource+ nil "v1.37.2-gr8s.8")
                                (gr8s.store::pod-store-resources store))
                       upgrade)))))
      (record "Waiting" "OnReconnect")
      (is (equal "r.example/g@sha256:00" (gr8s.apiserver::node-awaited-release store "edge" "v1.37.2-gr8s.7")))
      (is (equal "r.example/g@sha256:00" (gr8s.apiserver::node-awaited-release store "edge" nil)))
      (is (null (gr8s.apiserver::node-awaited-release store "edge" "v1.37.2-gr8s.8")) "it runs the release already")
      (is (null (gr8s.apiserver::node-awaited-release store "other" "v1.37.2-gr8s.7")))
      (record "Succeeded" "OnReconnect")
      (is (null (gr8s.apiserver::node-awaited-release store "edge" "v1.37.2-gr8s.7")) "a finished upgrade waits for no one"))))

(test upgrade-commands-name-a-release
  (let ((options (gr8s.server::parse-upgrade-options '("apply" "--to" "v1.37.2-gr8s.8" "--yes"))))
    (is (eq :upgrade-apply (getf options :command)))
    (is (equal "ghcr.io/atgreen/gr8s-packages:v1.37.2-gr8s.8" (gr8s.server::release-reference options)))
    (is (getf options :yes)))
  (is (equal "registry.lab:30500/gr8s/packages:v9"
             (gr8s.server::release-reference (gr8s.server::parse-upgrade-options '("plan" "--to" "registry.lab:30500/gr8s/packages:v9")))))
  (is (eq :upgrade-plan (getf (gr8s.server::parse-upgrade-options '("--to" "v1")) :command)) "plan is the default")
  (is (equal '("a.rpm" "b.deb")
             (getf (gr8s.server::parse-upgrade-options '("publish" "--to" "r.example/g:v1" "a.rpm" "b.deb")) :files)))
  (signals error (gr8s.server::parse-upgrade-options '("apply")))
  (signals error (gr8s.server::parse-upgrade-options '("bogus")))
  (is (equal "clusterupgrades.upgrade.gr8s.io"
             (gethash "name" (gethash "metadata" (gr8s.server::cluster-upgrade-crd))))))

(test a-registry-that-asks-for-basic-credentials-gets-them
  ;; zot reads anonymously and asks for a login, with Basic, to write.
  (uiop:with-temporary-file (:pathname scratch :keep nil)
    (let* ((directory (uiop:ensure-directory-pathname (format nil "~A.d" (namestring scratch))))
           (key (test-release-key))
           (objects (make-hash-table :test #'equal)) (uploads 0) (refused 0))
      (ensure-directories-exist directory)
      (let ((gr8s.upgrade::*registry-http*
              (lambda (url headers &key (method :get) content want-stream basic-authorization &allow-other-keys)
                (declare (ignore headers))
                (multiple-value-bind (status body response-headers)
                    (if (and (member method '(:post :put)) (not (equal basic-authorization '("pusher" "secret"))))
                        (progn (incf refused) (values 401 #() '((:www-authenticate . "Basic realm=\"Authorization Required\""))))
                        (fake-registry-answer objects (lambda () (incf uploads)) (puri:parse-uri url) method content))
                  (values (if want-stream (flexi-streams:make-in-memory-input-stream (coerce body '(vector (unsigned-byte 8)))) body)
                          status response-headers)))))
        (unwind-protect
             (let ((package (write-test-package directory "gr8s-linux-amd64" "an executable")))
               (signals gr8s.upgrade:upgrade-error
                 (gr8s.upgrade:publish-release-artifact "zot.example/gr8s/packages:v1" "v1.37.2-gr8s.9" (list package) key
                                                        :username "someone" :password "wrong"))
               (is (plusp refused))
               (is (stringp (gr8s.upgrade:publish-release-artifact "zot.example/gr8s/packages:v1" "v1.37.2-gr8s.9" (list package) key
                                                                   :username "pusher" :password "secret")))
               ;; Reading needs no login.
               (is (equal "v1.37.2-gr8s.9" (gr8s.upgrade:release-artifact-version
                                           (gr8s.upgrade:fetch-release-artifact "zot.example/gr8s/packages:v1" :keys (list key))))))
          (uiop:delete-directory-tree directory :validate t :if-does-not-exist :ignore))))))

(test a-downgrade-takes-the-agents-down-before-the-control-plane
  ;; An older control plane can't send an upgrade at all: in the lab, a member already
  ;; back on v1.37.2-gr8s.7 answered the next member's upgrade with "route not found".
  (is (equal '("gr8s-local" "pfwit" "gr8s2" "gvision")
             (mapcar #'first (plan-summary (lab-hosts :version "v1.37.2-gr8s.9") :allow-downgrade t)))))
