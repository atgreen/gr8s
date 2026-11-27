;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Checked content from browser Pods (podster-23v9.8, docs/design-browser-nodes.md).
;;;;
;;;; Whoever runs a browser node can change anything its Pods do, so nothing they serve
;;;; can be taken on trust, and nothing short of attestation, which browsers don't offer,
;;;; can prove a response was computed faithfully. What the server can know is the content:
;;;; it pulled the image and checked every layer against its digest, so it knows every
;;;; byte a static web server in that image may serve. The join listener therefore fronts a
;;;; Service of browser Pods, asks one of them over the Pod network, and passes the
;;;; response on only when its body is, byte for byte, the file the image holds at that
;;;; path. Any other answer is tampering: the request fails and the node is tainted
;;;; NoExecute, so its Pods leave it. A page that passes may name the facts the server
;;;; vouches for (the node, the Pod, the image) through placeholders the server fills in
;;;; after the check.

(in-package #:gr8s.server)

(defparameter +browser-content-root-annotation+ "gr8s.io/verified-content-root"
  "The Service annotation naming the directory, in its Pods' image, the content they serve
comes from. Only Services that have it are fronted.")

(defparameter +browser-tampered-taint+
  '("key" "gr8s.io/tampered" "value" "true" "effect" "NoExecute")
  "The taint a browser node gets once it has served what its image doesn't hold.")

(defparameter +browser-content-limit+ (* 4 1024 1024)
  "The largest response body a browser Pod's checked content may have.")

;;; What an image holds: each regular file's path and digest, its layers applied in order
;;; with their whiteouts, as a container would see it.

(defun tar-header-string (header start length)
  (let ((end (or (position 0 header :start start :end (+ start length)) (+ start length))))
    (map 'string #'code-char (subseq header start end))))

(defun tar-header-octal (header start length)
  (or (parse-integer (string-trim '(#\Space #\Nul) (tar-header-string header start length))
                     :radix 8 :junk-allowed t)
      0))

(defun pax-path (records)
  "The path in the PAX extended header RECORDS (octets), or NIL."
  (let ((text (trivial-utf-8:utf-8-bytes-to-string records)) (start 0))
    (loop for space = (position #\Space text :start start)
          while space
          do (let* ((length (parse-integer text :start start :end space))
                    (record (subseq text (1+ space) (+ start length -1))))
               (when (uiop:string-prefix-p "path=" record)
                 (return (subseq record 5)))
               (incf start length)))))

(defun image-path (name)
  "NAME from a layer, as an absolute path with no trailing slash."
  (let ((path (string-left-trim "/" (if (uiop:string-prefix-p "./" name) (subseq name 2) name))))
    (concatenate 'string "/" (string-right-trim "/" path))))

(defun map-tar-entries (function stream)
  "Call FUNCTION with each entry's path, type character, link target and a function giving
its contents' digest, for the tar archive on STREAM."
  (let ((header (make-array 512 :element-type '(unsigned-byte 8)))
        (buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (long-name nil))
    (flet ((read-block () (= 512 (read-sequence header stream)))
           (skip (count)
             (let ((left count))
               (loop while (plusp left)
                     do (let ((count (read-sequence buffer stream :end (min left (length buffer)))))
                          (when (zerop count) (return))
                          (decf left count))))))
      (loop while (and (read-block) (find-if #'plusp header))
            do (let* ((size (tar-header-octal header 124 12))
                      (type (code-char (aref header 156)))
                      (prefix (if (string= "ustar" (tar-header-string header 257 5))
                                  (tar-header-string header 345 155) ""))
                      (name (or (shiftf long-name nil)
                                (if (plusp (length prefix))
                                    (format nil "~A/~A" prefix (tar-header-string header 0 100))
                                    (tar-header-string header 0 100)))))
                 (case type
                   ((#\L #\x)
                    (let ((data (make-array size :element-type '(unsigned-byte 8))))
                      (read-sequence data stream)
                      (skip (- (* 512 (ceiling size 512)) size))
                      (setf long-name (if (char= type #\L)
                                          (string-right-trim '(#\Nul) (trivial-utf-8:utf-8-bytes-to-string data))
                                          (pax-path data)))))
                   (t
                    (let ((consumed nil))
                      (funcall function (image-path name) type (tar-header-string header 157 100)
                               (lambda ()
                                 (setf consumed t)
                                 (let ((digester (ironclad:make-digest :sha256)) (left size))
                                   (loop while (plusp left)
                                         do (let ((count (read-sequence buffer stream :end (min left (length buffer)))))
                                              (when (zerop count) (error "a layer ended inside ~A" name))
                                              (ironclad:update-digest digester buffer :end count)
                                              (decf left count)))
                                   (skip (- (* 512 (ceiling size 512)) size))
                                   (ironclad:byte-array-to-hex-string (ironclad:produce-digest digester)))))
                      (unless consumed (skip (* 512 (ceiling size 512))))))))))))

(defun apply-layer-files (files stream)
  "Apply the tar layer on STREAM to FILES, path -> hex digest: its whiteouts remove what
earlier layers put there, its regular files and hard links add theirs."
  (map-tar-entries
   (lambda (path type link digest)
     (let* ((slash (position #\/ path :from-end t))
            (directory (subseq path 0 slash))
            (base (subseq path (1+ slash))))
       (flet ((remove-under (root)
                (let ((prefix (concatenate 'string root "/")))
                  (loop for key in (loop for key being the hash-keys of files collect key)
                        when (or (string= key root) (uiop:string-prefix-p prefix key))
                          do (remhash key files)))))
         (cond ((string= base ".wh..wh..opq") (remove-under directory))
               ((uiop:string-prefix-p ".wh." base)
                (remove-under (format nil "~A/~A" directory (subseq base 4))))
               ((member type '(#\0 #\Nul #\7)) (setf (gethash path files) (funcall digest)))
               ((char= type #\1)
                (let ((target (gethash (image-path link) files)))
                  (if target (setf (gethash path files) target) (remhash path files))))
               (t (remhash path files))))))
   stream))

(defun browser-image-files (images reference)
  "The regular files of REFERENCE's image, which the server must have resolved: a table
of path -> hex digest. Computed from the cached layers once and remembered."
  (or (bt:with-lock-held ((browser-images-lock images))
        (gethash reference (browser-images-files images)))
      (let ((image (bt:with-lock-held ((browser-images-lock images))
                     (gethash reference (browser-images-resolved images))))
            (files (make-hash-table :test #'equal)))
        (unless image (error 'runtime-error :message (format nil "~A has not been resolved here" reference)))
        (loop for layer across (gethash "layers" image)
              for path = (browser-image-layer-file images (gethash "digest" layer))
              do (with-open-file (raw path :element-type '(unsigned-byte 8))
                   (if (search "gzip" (gethash "mediaType" layer ""))
                       (apply-layer-files files (chipz:make-decompressing-stream 'chipz:gzip raw))
                       (apply-layer-files files raw))))
        (bt:with-lock-held ((browser-images-lock images))
          (setf (gethash reference (browser-images-files images)) files)))))

(defun browser-content-file (root path)
  "The file under ROOT a web server answers PATH from: a directory's index.html."
  (let ((path (car (uiop:split-string path :separator "?"))))
    (format nil "~A~A~:[~;index.html~]" (string-right-trim "/" root) path
            (or (zerop (length path)) (char= #\/ (char path (1- (length path))))))))

;;; Serving

(defun browser-content-path-p (segments)
  "Whether SEGMENTS, the request path after /verified/NAMESPACE/SERVICE/, is one a tab may
be asked for: each segment a plain name (no empty segment, except the last for a
directory's index, no . or .., nothing escaped), so the path the Pod's web server sees
names the file the server checks."
  (loop for (segment . more) on segments
        always (if (zerop (length segment))
                   (null more)
                   (and (not (member segment '("." "..") :test #'string=))
                        (every (lambda (char) (and (graphic-char-p char) (char/= char #\\) (char/= char #\%)))
                               segment)))))

(defun browser-content-verdict (expected status digest)
  "What a tab's answer proves, for a file the image holds as EXPECTED (a SHA-256 in hex):
:serve when it answered 200 with that file; :tampered when it answered 200 with anything
else, as only a tab serving what its image doesn't hold does; :unavailable for any other
status, which an honest tab can give (busy, restarting), so it is no proof."
  (cond ((/= status 200) :unavailable)
        ((string= digest expected) :serve)
        (t :tampered)))

(defun html-escape (text)
  (with-output-to-string (out)
    (loop for char across text
          do (case char
               (#\< (write-string "&lt;" out)) (#\> (write-string "&gt;" out))
               (#\& (write-string "&amp;" out)) (#\" (write-string "&quot;" out))
               (t (write-char char out))))))

(defun fill-browser-content (html facts)
  "HTML with each <!--gr8s:KEY--> placeholder replaced by FACTS' KEY, escaped."
  (cl-ppcre:regex-replace-all
   "<!--gr8s:([a-z-]+)-->" html
   (lambda (match key)
     (let ((value (cdr (assoc key facts :test #'string=))))
       (if value (html-escape value) match)))
   :simple-calls t))

(defun browser-content-backends (acceptor service)
  "The browser Pods hosted here that SERVICE selects, each as (runtime node pod address)."
  (let* ((store (virtual-node-host-store (browser-join-nodes acceptor)))
         (namespace (gethash "namespace" (gethash "metadata" service)))
         (selector (gethash "selector" (gethash "spec" service) (core-object))))
    (when (plusp (hash-table-count selector))
      (loop for node being the hash-keys of (browser-join-runtimes acceptor) using (hash-value runtime)
            nconc (loop for key being the hash-keys of (browser-runtime-names runtime) using (hash-value uid)
                        for slash = (position #\/ key)
                        for pod = (and (string= namespace (subseq key 0 slash))
                                       (ignore-errors (gr8s.store:get-pod store namespace (subseq key (1+ slash)))))
                        for runtime-pod = (gethash uid (gr8s.runtime::fake-runtime-pods runtime))
                        for labels = (and pod (gethash "labels" (gethash "metadata" (gr8s.model::pod-to-object pod)) (core-object)))
                        when (and pod runtime-pod (equal uid (gr8s.model::pod-uid pod))
                                  (loop for key being the hash-keys of selector using (hash-value value)
                                        always (equal value (gethash key labels)))
                                  (plusp (length (or (gr8s.runtime::runtime-pod-pod-ip runtime-pod) ""))))
                          collect (list runtime node pod (gr8s.runtime::runtime-pod-pod-ip runtime-pod)))))))

(defun browser-content-image (pod port)
  "The image of POD's container serving PORT, or of its first container."
  (let ((containers (gethash "containers" (gethash "spec" (gr8s.model::pod-to-object pod)))))
    (gethash "image" (or (find-if (lambda (container)
                                    (some (lambda (entry) (eql port (gethash "containerPort" entry)))
                                          (gethash "ports" container #())))
                                  containers)
                         (aref containers 0)))))

(defun taint-tampered-browser-node (acceptor node reason)
  "Taint NODE NoExecute for serving what its image doesn't hold, so its Pods leave it."
  (let* ((store (virtual-node-host-store (browser-join-nodes acceptor)))
         (record (ignore-errors (gr8s.controllers::get-node store node))))
    (incf (browser-join-tampered acceptor))
    (format *error-output* "gr8s browser node ~A tampered with its content: ~A~%" node reason)
    (when (and record (notany (lambda (taint) (equal "gr8s.io/tampered" (gethash "key" taint)))
                              (gr8s.model::node-record-taints record)))
      (gr8s.resources::set-node-labels-and-taints
       store node (core-object)
       (concatenate 'vector (gr8s.model::node-record-taints record)
                    (vector (apply #'core-object +browser-tampered-taint+)))))))

(defun browser-content-forwarded-headers (header client-address)
  "What checked content tells a browser Pod about the visitor, as (name . value) headers,
as a reverse proxy would: Referer, Accept-Language and how and where the request came in;
with CLIENT-ADDRESS, the visitor's address as X-Forwarded-For and X-Real-IP. HEADER gives
a header of the visitor's request by keyword, or NIL. The User-Agent goes separately."
  (append
   (loop for (key name) in '((:referer "Referer") (:accept-language "Accept-Language")
                             (:x-forwarded-proto "X-Forwarded-Proto"))
         for value = (funcall header key)
         when value collect (cons name value))
   (let ((host (or (funcall header :x-forwarded-host) (funcall header :host))))
     (when host (list (cons "X-Forwarded-Host" host))))
   (when client-address
     (list (cons "X-Forwarded-For" client-address) (cons "X-Real-IP" client-address)))))

(defun fetch-browser-pod (address port path &key user-agent headers)
  "GET PATH from the Pod at ADDRESS:PORT over the Pod network, sending USER-AGENT and
HEADERS for the visitor: (values status body content-type), the body as octets and no
larger than the limit."
  (multiple-value-bind (stream status headers)
      (drakma:http-request (format nil "http://~A:~D~A" address port path)
                           :want-stream t :force-binary t :redirect nil :connection-timeout 10
                           :user-agent (or user-agent :drakma)
                           :additional-headers (cons '("Accept-Encoding" . "identity") headers))
    (unwind-protect
         (let ((body (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
               (buffer (make-array 16384 :element-type '(unsigned-byte 8))))
           (loop for count = (read-sequence buffer stream)
                 while (plusp count)
                 do (when (> (+ (length body) count) +browser-content-limit+)
                      (error "the response is larger than ~D bytes" +browser-content-limit+))
                    (loop for index below count do (vector-push-extend (aref buffer index) body)))
           (values status (coerce body '(simple-array (unsigned-byte 8) (*)))
                   (drakma:header-value :content-type headers)))
      (close stream))))

(defun serve-browser-content (acceptor request path)
  "Answer REQUEST for /verified/NAMESPACE/SERVICE/REST from one of SERVICE's browser Pods,
when what the Pod answers is the file its image holds there. Only a file the image holds
is asked for; a Pod that answers 200 with anything else has its node tainted, and any
other answer just fails the request."
  (destructuring-bind (&optional namespace name &rest rest)
      (uiop:split-string (subseq path (length "/verified/")) :separator '(#\/))
    (flet ((fail (code text)
             (setf (hunchentoot:return-code*) code (hunchentoot:content-type*) "text/plain; charset=utf-8")
             (return-from serve-browser-content text)))
      (unless (member (hunchentoot:request-method request) '(:get :head))
        (fail 405 "checked content is only read"))
      (let* ((store (virtual-node-host-store (browser-join-nodes acceptor)))
             (service (and namespace name
                           (find name (ignore-errors (gr8s.resources::list-core-resources store "services" namespace))
                                 :key (lambda (service) (gethash "name" (gethash "metadata" service)))
                                 :test #'equal)))
             (root (and service (gethash +browser-content-root-annotation+
                                         (gethash "annotations" (gethash "metadata" service) (core-object)))))
             (port (and service (let ((entry (aref (gethash "ports" (gethash "spec" service) #((core-object))) 0)))
                                  (let ((target (gethash "targetPort" entry (gethash "port" entry))))
                                    (and (integerp target) target)))))
             (backends (and root port (browser-content-backends acceptor service)))
             (request-path (format nil "/~{~A~^/~}" rest)))
        (unless root (fail 404 "no Service here serves checked content by that name"))
        (unless (browser-content-path-p rest) (fail 404 "not found"))
        (unless backends (fail 503 "no browser is serving this right now; open the join page in one"))
        (destructuring-bind (runtime node pod address) (elt backends (random (length backends)))
          (let* ((reference (browser-content-image pod port))
                 (image (bt:with-lock-held ((browser-images-lock (browser-runtime-images runtime)))
                          (gethash reference (browser-images-resolved (browser-runtime-images runtime)))))
                 (labels (or (and image (gethash "labels" image)) (core-object)))
                 (files (handler-case (browser-image-files (browser-runtime-images runtime) reference)
                          (error (condition) (fail 502 (format nil "~A: ~A" reference condition)))))
                 (file (browser-content-file root request-path))
                 (expected (gethash file files)))
            ;; Only a file the image holds is asked for: what a tab answers for anything
            ;; else proves nothing, and must not cost it its Pods (podster-k8oi).
            (unless expected (fail 404 "not found"))
            (multiple-value-bind (status body content-type)
                (handler-case (fetch-browser-pod
                               address port request-path
                               :user-agent (hunchentoot:header-in :user-agent request)
                               :headers (browser-content-forwarded-headers
                                         (lambda (name) (hunchentoot:header-in name request))
                                         (and (browser-join-forward-client-address acceptor)
                                              (browser-join-client-address acceptor request))))
                  (error (condition) (fail 502 (format nil "the browser didn't answer: ~A" condition))))
              (let ((digest (ironclad:byte-array-to-hex-string (ironclad:digest-sequence :sha256 body))))
                (ecase (browser-content-verdict expected status digest)
                  (:unavailable
                   (fail 502 (format nil "The browser serving this couldn't answer (HTTP ~D). Reload to be served by another." status)))
                  (:tampered
                   (taint-tampered-browser-node
                    acceptor node (format nil "~A answered ~A with something that doesn't match ~A"
                                          (gr8s.model::pod-name pod) file reference))
                   (fail 502 "The browser serving this answered with something other than what its image holds, so it was turned away. Reload to be served by another."))
                  (:serve
                   (incf (browser-join-verified acceptor))
                   (setf (hunchentoot:content-type*) (or content-type "application/octet-stream")
                         (hunchentoot:header-out "X-Gr8s-Content-Digest") (format nil "sha256:~A" digest)
                         (hunchentoot:header-out "X-Gr8s-Served-By") node
                         (hunchentoot:header-out "Cache-Control") "no-store")
                   (if (search "text/html" (or content-type ""))
                       (fill-browser-content
                        (trivial-utf-8:utf-8-bytes-to-string body)
                        (list (cons "node" node)
                              (cons "pod" (format nil "~A/~A" namespace (gr8s.model::pod-name pod)))
                              (cons "browser" (or (browser-runtime-browser runtime) "a web browser"))
                              (cons "image" reference)
                              (cons "image-digest" (gethash "digest" image ""))
                              (cons "image-base" (format nil "~@[~A~]~@[ ~A~]" (gethash "name" labels) (gethash "version" labels)))
                              (cons "image-summary" (gethash "summary" labels ""))
                              (cons "digest" (format nil "sha256:~A" digest))
                              (cons "file" file)
                              (cons "up" (let ((seconds (- (get-universal-time) (browser-runtime-joined runtime))))
                                           (format nil "~D min ~D s" (floor seconds 60) (mod seconds 60))))
                              (cons "served-at" (multiple-value-bind (s m h) (decode-universal-time (get-universal-time) 0)
                                                  (format nil "~2,'0D:~2,'0D:~2,'0D UTC" h m s)))))
                       body)))))))))))

(defparameter +browser-names+ '("Chrome" "Chromium" "Edge" "Firefox" "Safari" "Opera" "Brave" "Vivaldi" "Samsung Internet")
  "The browser names a tab may say it is.")

(defparameter +browser-systems+ '("Windows" "macOS" "Linux" "Android" "iOS" "ChromeOS")
  "The systems a tab may say it runs on.")

(defun browser-description (hello)
  "What browser HELLO says its tab is, as \"Firefox on Linux\": only names from fixed
lists, since the tab is believed about nothing else; NIL when it names none of them."
  (let* ((browser (and (hash-table-p (gethash "browser" hello)) (gethash "browser" hello)))
         (name (and browser (find (gethash "name" browser) +browser-names+ :test #'equal)))
         (system (and browser (find (gethash "os" browser) +browser-systems+ :test #'equal))))
    (and name (format nil "~A~@[ on ~A~]" name system))))
