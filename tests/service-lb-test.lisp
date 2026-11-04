;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Pin the byte-order contract between the control-plane map encoders
;;;; (src/service-lb.lisp) and the cgroup/connect4 program that reads them
;;;; (src/service-lb-program.lisp), and prove the program JIT-compiles in-process
;;;; to loadable specs with no ELF and no kernel privileges.

(in-package #:gr8s/tests)
(def-suite service-lb :in gr8s)
(in-suite service-lb)

;;; Byte-order contract.  A ClusterIP:port and a backend addr:port encode to the
;;; exact octets the eBPF program composes and copies into the socket address.

(test service-lb-vip-key-byte-layout
  ;; (vip << 16) | htons(port), serialized little-endian, where vip is the
  ;; address octets read little-endian (network-order bytes on a LE host).
  (is (equalp #(#x00 #x50 #x0A #x60 #x00 #x0A #x00 #x00)
              (gr8s::service-lb-vip-key "10.96.0.10" 80)))
  ;; Distinct ports and addresses must not collide into the same key.
  (is (not (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80)
                   (gr8s::service-lb-vip-key "10.96.0.10" 443))))
  (is (not (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80)
                   (gr8s::service-lb-vip-key "10.96.0.11" 80)))))

(test service-lb-service-value-byte-layout
  ;; count u16 @0, base slot u32 @4, both little-endian (logical integers).
  (is (equalp #(#x01 #x00 #x00 #x00 #x07 #x00 #x00 #x00)
              (gr8s::service-lb-service-value 1 7)))
  (is (equalp #(#x00 #x02 #x00 #x00 #xD2 #x04 #x00 #x00)
              (gr8s::service-lb-service-value 512 1234))))

(test service-lb-backend-byte-layout
  ;; Backend slot key is little-endian; addr u32 @0 and port u16 @4 are network
  ;; byte order so the program copies them verbatim into user_ip4 / user_port.
  (is (equalp #(#x07 #x00 #x00 #x00) (gr8s::service-lb-backend-key 7)))
  (is (equalp #(#x0A #x58 #x01 #x05 #x1F #x90 #x00 #x00)
              (gr8s::service-lb-backend-value "10.88.1.5" 8080))))

(test service-lb-ports-are-validated
  (signals error (gr8s::service-lb-vip-key "10.96.0.10" 0))
  (signals error (gr8s::service-lb-vip-key "10.96.0.10" 70000))
  (signals error (gr8s::service-lb-backend-value "10.88.1.5" 0)))

(test service-lb-entries-assign-consecutive-slots
  (multiple-value-bind (vip-key service-value backends)
      (gr8s::service-lb-entries "10.96.0.10" 80 5
                                '(("10.88.1.5" . 8080) ("10.88.2.7" . 8080)))
    (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) vip-key))
    ;; Two backends, base slot 5.
    (is (equalp (gr8s::service-lb-service-value 2 5) service-value))
    (is (= 2 (length backends)))
    (is (equalp (gr8s::service-lb-backend-key 5) (car (first backends))))
    (is (equalp (gr8s::service-lb-backend-value "10.88.1.5" 8080) (cdr (first backends))))
    (is (equalp (gr8s::service-lb-backend-key 6) (car (second backends))))
    (is (equalp (gr8s::service-lb-backend-value "10.88.2.7" 8080) (cdr (second backends))))))

;;; In-process JIT: the program compiles to loadable specs with no ELF. Pure
;;; userspace; needs no CAP_BPF and no kernel, so it runs in the ordinary suite.

(test service-lb-program-compiles-in-process
  (multiple-value-bind (map-specs prog-specs) (gr8s::compile-service-lb)
    ;; Exactly the two maps, with the key/value sizes the encoders target.
    (is (= 2 (length map-specs)))
    (let ((service (find "gr8s_service_v4" map-specs
                         :key (lambda (s) (getf s :name)) :test #'string=))
          (backend (find "gr8s_backend_v4" map-specs
                         :key (lambda (s) (getf s :name)) :test #'string=)))
      (is (not (null service)))
      (is (not (null backend)))
      (is (= 8 (getf service :key-size)))
      (is (= 8 (getf service :value-size)))
      (is (= 4 (getf backend :key-size)))
      (is (= 8 (getf backend :value-size))))
    ;; One connect4 program with real, 8-byte-aligned instruction bytes and the
    ;; map-fd relocations the loader patches in (one per map lookup, at least).
    (is (= 1 (length prog-specs)))
    (let* ((prog (first prog-specs))
           (insns (getf prog :insns)))
      (is (string= "cgroup/connect4" (getf prog :section)))
      (is (plusp (length insns)))
      (is (zerop (mod (length insns) 8)))
      (is (>= (length (getf prog :relocs)) 2)))))

;;; Dataplane lifecycle.  Every kernel operation (map creation, pinning,
;;; program load, cgroup attach, detach) is injected, so the orchestration is
;;; exercised without CAP_BPF.  Fake fds use large numbers that cannot collide
;;; with a real descriptor, so the ignored sb-posix:close calls are harmless.

(defun fake-lb-map (name fd)
  (cons name (whistler/loader::make-map-info
              :name name :type 2 :key-size 8 :value-size 8
              :max-entries 1 :flags 0 :fd fd)))

(defun fake-lb-program (fd)
  (whistler/loader::make-prog-info
   :name "gr8s_service_lb" :section-name "cgroup/connect4"
   :type 18 :insns #() :fd fd))

(test service-lb-dataplane-start-pins-then-loads-then-attaches
  (let ((pinned nil) (attach-args nil) (load-saw-maps nil))
    (let ((dataplane
            (gr8s::start-service-lb-dataplane
             "/sys/fs/cgroup/gr8s" "/run/gr8s/bpf/service-lb"
             :compile (lambda () (values :map-specs :program-specs))
             :create-maps (lambda (specs)
                            (is (eq :map-specs specs))
                            (list (fake-lb-map "gr8s_service_v4" 900001)
                                  (fake-lb-map "gr8s_backend_v4" 900002)))
             :ensure-directory (lambda (path) (declare (ignore path)) t)
             :pin-map (lambda (map path)
                        (push (cons (whistler/loader:map-info-fd map) (namestring path)) pinned))
             :load-programs (lambda (specs maps)
                              (is (eq :program-specs specs))
                              (setf load-saw-maps maps)
                              (list (cons "gr8s_service_lb" (fake-lb-program 900003))))
             :attach (lambda (program-fd cgroup) (setf attach-args (list program-fd cgroup)) :attachment))))
      ;; Both maps are pinned, under the given bpffs directory, by their names.
      (is (= 2 (length pinned)))
      (is (member "/run/gr8s/bpf/service-lb/gr8s_service_v4" pinned
                  :key #'cdr :test #'string=))
      (is (member "/run/gr8s/bpf/service-lb/gr8s_backend_v4" pinned
                  :key #'cdr :test #'string=))
      ;; Pinning happens before the program load (so a failed load leaves
      ;; discoverable maps): the loader sees the already-created maps.
      (is (= 2 (length load-saw-maps)))
      ;; The program is attached to the given cgroup by its loaded fd.
      (is (equal (list 900003 "/sys/fs/cgroup/gr8s") attach-args))
      (is (eq :attachment (gr8s::service-lb-dataplane-attachment dataplane)))
      (is (not (null (gr8s::service-lb-service-table dataplane))))
      (is (not (null (gr8s::service-lb-backend-table dataplane)))))))

(test service-lb-dataplane-start-rolls-back-pins-on-load-failure
  (let ((removed nil))
    (signals error
      (gr8s::start-service-lb-dataplane
       "/sys/fs/cgroup/gr8s" "/run/gr8s/bpf/service-lb"
       :compile (lambda () (values :map-specs :program-specs))
       :create-maps (lambda (specs) (declare (ignore specs))
                      (list (fake-lb-map "gr8s_service_v4" 900001)
                            (fake-lb-map "gr8s_backend_v4" 900002)))
       :ensure-directory (lambda (path) (declare (ignore path)) t)
       :pin-map (lambda (map path) (declare (ignore map path)) t)
       :remove-path (lambda (path) (push (namestring path) removed))
       :load-programs (lambda (specs maps) (declare (ignore specs maps))
                        (error "verifier rejected the program"))
       :attach (lambda (program-fd cgroup) (declare (ignore program-fd cgroup)) :attachment)))
    ;; A failed load removes every pin it had created.
    (is (= 2 (length removed)))
    (is (member "/run/gr8s/bpf/service-lb/gr8s_service_v4" removed :test #'string=))
    (is (member "/run/gr8s/bpf/service-lb/gr8s_backend_v4" removed :test #'string=))))

(test service-lb-dataplane-stop-detaches-and-removes-pins
  (let ((detached nil) (removed nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :cgroup-path "/sys/fs/cgroup/gr8s"
                    :pin-directory "/run/gr8s/bpf/service-lb/"
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001)
                                (fake-lb-map "gr8s_backend_v4" 900002))
                    :program (fake-lb-program 900003)
                    :attachment :attachment)))
    (gr8s::stop-service-lb-dataplane
     dataplane
     :detach (lambda (attachment) (push attachment detached))
     :remove-path (lambda (path) (push (namestring path) removed)))
    (is (equal '(:attachment) detached))
    (is (null (gr8s::service-lb-dataplane-attachment dataplane)))
    (is (= 2 (length removed)))
    (is (member "/run/gr8s/bpf/service-lb/gr8s_service_v4" removed :test #'string=))))

(test service-lb-dataplane-stop-can-keep-pins
  (let ((removed nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :pin-directory "/run/gr8s/bpf/service-lb/"
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001))
                    :program (fake-lb-program 900003)
                    :attachment :attachment)))
    (gr8s::stop-service-lb-dataplane
     dataplane :remove-pins nil
     :detach (lambda (attachment) (declare (ignore attachment)) t)
     :remove-path (lambda (path) (push (namestring path) removed)))
    ;; Keeping pins across a restart removes nothing.
    (is (null removed))))

(test service-lb-write-service-fills-backends-before-vip
  ;; Backends must land before the service entry, so the program never reads a
  ;; VIP whose slots are missing.  Record the update order and payloads.
  (let ((writes nil)
        (dataplane (gr8s::%make-service-lb-dataplane
                    :maps (list (fake-lb-map "gr8s_service_v4" 900001)
                                (fake-lb-map "gr8s_backend_v4" 900002)))))
    (gr8s::service-lb-write-service
     dataplane "10.96.0.10" 80 3 '(("10.88.1.5" . 8080) ("10.88.2.7" . 8080))
     :update (lambda (map key value)
               (push (list (whistler/loader:map-info-fd map) key value) writes)))
    (setf writes (nreverse writes))
    ;; Two backend writes (fd 900002) then the service write (fd 900001).
    (is (equal '(900002 900002 900001) (mapcar #'first writes)))
    (is (equalp (gr8s::service-lb-backend-key 3) (second (first writes))))
    (is (equalp (gr8s::service-lb-backend-value "10.88.1.5" 8080) (third (first writes))))
    (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) (second (third writes))))
    (is (equalp (gr8s::service-lb-service-value 2 3) (third (third writes))))))

(test service-lb-pin-directory-is-under-state
  (is (string= "/var/lib/gr8s/containerd/bpf/service-lb/"
               (gr8s::service-lb-pin-directory "/var/lib/gr8s"))))

;;; Controller: converge Service/endpoint state into the maps.  Services are
;;; plain core objects and the endpoint lookup and map ops are injected, so no
;;; store and no kernel are needed.

(defun fake-lb-service (cluster-ip &key (ports '(80)) external-name)
  (let ((spec (gr8s::core-object
               "clusterIP" cluster-ip
               "type" (if external-name "ExternalName" "ClusterIP")
               "selector" (gr8s::core-object "app" "web")
               "ports" (coerce (mapcar (lambda (p) (gr8s::core-object "port" p)) ports) 'vector))))
    (when external-name (setf (gethash "externalName" spec) external-name))
    (gr8s::core-object
     "metadata" (gr8s::core-object "name" "svc" "namespace" "default" "uid" cluster-ip)
     "spec" spec)))

(test service-lb-plan-excludes-ineligible-services
  ;; Headless (None), the API Service, and ExternalName never reach the maps.
  (let ((services (list (fake-lb-service "None")
                        (fake-lb-service "10.96.0.1")
                        (fake-lb-service "10.96.0.9" :external-name "db.example.com")
                        (fake-lb-service "10.96.0.10"))))
    (multiple-value-bind (service-entries backend-entries slots)
        (gr8s::service-lb-plan services (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080))))
      (is (= 1 (length service-entries)))
      (is (= 1 (length backend-entries)))
      (is (= 1 slots))
      (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) (car (first service-entries)))))))

(test service-lb-plan-packs-backends-deterministically
  (let ((services (list (fake-lb-service "10.96.0.10" :ports '(80))
                        (fake-lb-service "10.96.0.5" :ports '(80 443)))))
    (flet ((endpoints (service port)
             (let ((ip (gethash "clusterIP" (gethash "spec" service)))
                   (number (gethash "port" port)))
               (cond ((and (equal ip "10.96.0.10") (= number 80))
                      '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
                     ((and (equal ip "10.96.0.5") (= number 80)) '(("10.88.2.1" 9090)))
                     (t '())))))               ; 10.96.0.5:443 has no ready backends
      (multiple-value-bind (service-entries backend-entries slots)
          (gr8s::service-lb-plan services #'endpoints)
        ;; "10.96.0.10" sorts before "10.96.0.5"; slots pack 0,1 then 2.
        (is (= 3 (length service-entries)))
        (is (= 3 (length backend-entries)))
        (is (= 3 slots))
        (is (equalp (gr8s::service-lb-vip-key "10.96.0.10" 80) (car (first service-entries))))
        (is (equalp (gr8s::service-lb-service-value 2 0) (cdr (first service-entries))))
        (is (equalp (gr8s::service-lb-backend-value "10.88.1.5" 8080) (cdr (first backend-entries))))
        ;; A port with no ready backends still gets a zero-count entry (passthrough);
        ;; its base is the slot counter after the two populated ports (0,1 then 2).
        (is (equalp (gr8s::service-lb-service-value 0 3) (cdr (third service-entries))))))))

(defun make-fake-lb-controller ()
  (gr8s::make-service-lb-controller
   nil
   (gr8s::%make-service-lb-dataplane
    :maps (list (fake-lb-map "gr8s_service_v4" 1) (fake-lb-map "gr8s_backend_v4" 2)))))

(test service-lb-converge-writes-backends-before-services-then-is-idempotent
  (let ((controller (make-fake-lb-controller))
        (one-service (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80)))))
        (two-backends (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))))
    (let ((writes nil) (deletes nil))
      (gr8s::converge-service-lb-controller
       controller :list-services one-service :endpoints-of two-backends
       :update (lambda (m k v) (declare (ignore k v)) (push (whistler/loader:map-info-fd m) writes))
       :delete (lambda (m k) (declare (ignore k)) (push (whistler/loader:map-info-fd m) deletes)))
      ;; Two backend writes (map fd 2) then the one service write (map fd 1).
      (is (equal '(2 2 1) (nreverse writes)))
      (is (null deletes)))
    ;; Re-converging an unchanged plan writes and deletes nothing.
    (let ((touched nil))
      (gr8s::converge-service-lb-controller
       controller :list-services one-service :endpoints-of two-backends
       :update (lambda (m k v) (declare (ignore m k v)) (push t touched))
       :delete (lambda (m k) (declare (ignore m k)) (push t touched)))
      (is (null touched)))))

(test service-lb-converge-frees-slots-when-a-backend-leaves
  (let ((controller (make-fake-lb-controller)))
    ;; Start with two backends.
    (gr8s::converge-service-lb-controller
     controller
     :list-services (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80))))
     :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080) ("10.88.1.6" 8080)))
     :update (constantly nil) :delete (constantly nil))
    ;; Drop to one backend: slot 1 must be deleted from the backend map (fd 2).
    (let ((deletes nil))
      (gr8s::converge-service-lb-controller
       controller
       :list-services (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80))))
       :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080)))
       :update (constantly nil)
       :delete (lambda (m k) (push (list (whistler/loader:map-info-fd m) k) deletes)))
      (is (member (list 2 (gr8s::service-lb-backend-key 1)) deletes :test #'equalp)))))

(test service-lb-converge-withdraws-a-removed-service
  (let ((controller (make-fake-lb-controller)))
    (gr8s::converge-service-lb-controller
     controller
     :list-services (lambda () (list (fake-lb-service "10.96.0.10" :ports '(80))))
     :endpoints-of (lambda (s p) (declare (ignore s p)) '(("10.88.1.5" 8080)))
     :update (constantly nil) :delete (constantly nil))
    ;; Remove the Service entirely: its VIP key (fd 1) and freed slot 0 (fd 2) go.
    (let ((deletes nil))
      (gr8s::converge-service-lb-controller
       controller
       :list-services (lambda () nil)
       :endpoints-of (lambda (s p) (declare (ignore s p)) nil)
       :update (constantly nil)
       :delete (lambda (m k) (push (list (whistler/loader:map-info-fd m) k) deletes)))
      (is (member (list 1 (gr8s::service-lb-vip-key "10.96.0.10" 80)) deletes :test #'equalp))
      (is (member (list 2 (gr8s::service-lb-backend-key 0)) deletes :test #'equalp)))))
