(require :asdf)

;; The binary keeps the heap size of the SBCL that dumps it, so dump from one with the
;; size gr8s needs: a control plane and its local agent outgrow SBCL's 1 GB default.
;; "--dynamic-space-size SIZE" before gr8s's own arguments still overrides it.
(defparameter *gr8s-dynamic-space-size* (* 2 1024 1024 1024))

#+sbcl
(when (< (sb-ext:dynamic-space-size) *gr8s-dynamic-space-size*)
  (uiop:quit
   (sb-ext:process-exit-code
    (sb-ext:run-program sb-ext:*runtime-pathname*
                        (list "--core" (namestring sb-ext:*core-pathname*)
                              "--dynamic-space-size" (format nil "~DMB" (floor *gr8s-dynamic-space-size* (* 1024 1024)))
                              "--noinform" "--non-interactive" "--load" "scripts/build-native.lisp")
                        :output t :error t :input t))))

(asdf:load-asd (truename "gr8s.asd"))
(asdf:load-system :gr8s)
(gr8s.runtime::embed-runtime-assets #P"build/containerd/")

;; All endpoint pipelines use fixed in-image source. Preserve their compiled
;; specs in the dumped heap so the first CNI ADD only creates/loads kernel
;; objects: compiling the Service pipeline can exceed the CNI IPC deadline.
;; These are relocatable byte vectors and map descriptors, never live BPF FDs.
;; The loader patches a copy for each endpoint. Source-based runs retain the
;; same lazy compilation path through EGRESS-GUARD-SPECS.
(dolist (service-packets '(nil t :v2))
  (let* ((start (get-internal-real-time))
         (specs (gr8s.network::egress-guard-specs :service-packets service-packets)))
    (format t "build-native: prepared ~A endpoint pipeline (~D maps, ~D programs) in ~,3Fs~%"
            (case service-packets
              ((nil) "plain")
              (:v2 "v2 Service")
              (otherwise "Service"))
            (length (car specs)) (length (cdr specs))
            (/ (- (get-internal-real-time) start) internal-time-units-per-second))))

;; Embed a gzip of the collected third-party NOTICES (produced by `make
;; notices`) so the full attribution ships inside the single binary; `gr8s
;; notices` decompresses and prints it. salza2 is only needed here, at build.
(let ((notices #P"NOTICES"))
  (if (probe-file notices)
      (progn
        (asdf:load-system :salza2)
        (setf gr8s.server::*embedded-notices-gz*
              (uiop:symbol-call
               :salza2 :compress-data
               (trivial-utf-8:string-to-utf-8-bytes (uiop:read-file-string notices))
               (uiop:find-symbol* :gzip-compressor :salza2)))
        (format t "build-native: embedded NOTICES (~D bytes gzipped)~%"
                (length gr8s.server::*embedded-notices-gz*)))
      (warn "build-native: NOTICES missing; `gr8s notices` will be empty. Run `make notices`.")))

;; Bake the git-augmented version into the image. This build dumps with
;; save-lisp-and-die rather than asdf:program-op, so VERSION-STRING's program-op
;; hook never fires; set +GR8S-VERSION+ here instead, while the git repo is present.
(setf gr8s.foundation::+gr8s-version+ (version-string:make-version-string :gr8s :include-git-p t))

;; Base systems are supplied by the dumped image. Patch systems may depend on
;; them on hosts without this checkout; no ASDF operation should reload them.
(dolist (system (asdf:already-loaded-systems))
  (asdf:register-immutable-system system))

(defun gr8s-native-main ()
  ;; The runtime reads only a leading --dynamic-space-size or --control-stack-size, and
  ;; passes the rest on. Older wrappers end the runtime's options explicitly.
  (let ((arguments (uiop:command-line-arguments)))
    (uiop:quit (gr8s.server:main (if (equal (first arguments) "--end-runtime-options")
                              (rest arguments)
                              arguments)))))

(ensure-directories-exist #P"build/")

#+sbcl
;; Dump the executable as build/gr8s itself -- no launcher script. :accept-runtime-options
;; still honours a leading --dynamic-space-size/--control-stack-size and passes the rest to
;; gr8s, and gr8s-native-main tolerates a legacy --end-runtime-options prefix. gr8s-root-directory
;; derives GR8S_ROOT from this executable's own path.
(sb-ext:save-lisp-and-die
 #P"build/gr8s"
 :toplevel #'gr8s-native-main
 :executable t
 :save-runtime-options :accept-runtime-options
 :compression t
 :purify t)

#-sbcl
(error "Native executable builds currently require SBCL")
