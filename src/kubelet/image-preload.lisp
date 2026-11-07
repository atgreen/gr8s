;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Import image archives from the agent's images directory into containerd's
;;;; CRI namespace before Pods start, as k3s does with its airgap images. Each
;;;; archive goes through containerd's Transfer service, which names, stores and
;;;; unpacks it exactly as `ctr images import` would.

(in-package #:gr8s.kubelet)

(defparameter *image-archive-chunk-bytes* (* 32 1024)
  "The largest Data message containerd's own transfer streams send.")

(defparameter *image-archive-import-timeout* 3600
  "Seconds one archive's import may take, slow disks included.")

(defparameter *image-archive-import-prefix* "import-gr8s"
  "The name given to an archived image tagged only, without a repository; as `ctr import` does.")

(defun managed-containerd-images-directory (manager)
  "Return the directory whose image archives the agent imports at startup."
  (merge-pathnames "images/" (managed-containerd-state-directory manager)))

(defun image-archive-paths (directory)
  "Return DIRECTORY's image archives (*.tar) in name order."
  (sort (remove-if-not (lambda (path) (equalp "tar" (pathname-type path)))
                       (uiop:directory-files (uiop:ensure-directory-pathname directory)))
        #'string< :key #'namestring))

(defun containerd-any (type-url message)
  "Wrap MESSAGE as the google.protobuf.Any containerd expects, naming its containerd type."
  (make-instance 'gr8s.containerd.transfer.v1::any
                 :type-url type-url
                 :value (coerce (ag-proto:serialize-to-bytes message) '(simple-array (unsigned-byte 8) (*)))))

(defun containerd-transfer-platform (platform)
  "Parse an OS/ARCH[/VARIANT] PLATFORM string into containerd's Platform message."
  (destructuring-bind (os architecture &optional (variant ""))
      (uiop:split-string platform :separator "/")
    (make-instance 'gr8s.containerd.transfer.v1::platform
                   :os os :architecture architecture :variant variant)))

(defun image-archive-import-store (platform snapshotter)
  "Describe where an imported archive goes: named from its own references and unpacked
for PLATFORM into SNAPSHOTTER, as `ctr images import` without --base-name does."
  (let ((target (containerd-transfer-platform platform)))
    (make-instance 'gr8s.containerd.transfer.v1::image-store
                   :platforms (list target)
                   :extra-references
                   (list (make-instance 'gr8s.containerd.transfer.v1::image-reference
                                        :name *image-archive-import-prefix* :is-prefix t :allow-overwrite t))
                   :unpacks
                   (list (make-instance 'gr8s.containerd.transfer.v1::unpack-configuration
                                        :platform target :snapshotter snapshotter)))))

(defun image-archive-window-credit (message)
  "Return the bytes a containerd WindowUpdate MESSAGE lets the sender add."
  (unless (equal "containerd.types.transfer.WindowUpdate"
                 (gr8s.containerd.transfer.v1::type-url message))
    (error 'runtime-error :message (format nil "containerd sent ~A on an image stream"
                                           (gr8s.containerd.transfer.v1::type-url message))))
  (gr8s.containerd.transfer.v1::update
   (ag-proto:deserialize-from-bytes 'gr8s.containerd.transfer.v1::window-update
                                    (gr8s.containerd.transfer.v1::value message))))

(defun send-image-archive (input send receive)
  "Send INPUT's bytes as containerd transfer Data messages through SEND, within the
credit containerd grants in WindowUpdate messages that RECEIVE returns."
  (let ((buffer (make-array *image-archive-chunk-bytes* :element-type '(unsigned-byte 8)))
        (credit 0))
    (loop
      (loop while (<= credit 0)
            do (let ((message (funcall receive)))
                 (unless message
                   (error 'runtime-error :message "containerd closed the image stream before the archive was sent"))
                 (incf credit (image-archive-window-credit message))))
      (let ((count (read-sequence buffer input :end (min (length buffer) credit))))
        (when (zerop count) (return))
        (funcall send (containerd-any "containerd.types.transfer.Data"
                                      (make-instance 'gr8s.containerd.transfer.v1::data
                                                     :data (subseq buffer 0 count))))
        (decf credit count)))))

(defun import-image-archive (socket-path path &key platform snapshotter
                                                   (timeout *image-archive-import-timeout*))
  "Import the image archive at PATH into the CRI namespace through containerd's Transfer service."
  (let ((metadata (containerd-namespace-metadata))
        (id (format nil "gr8s-image-import-~36R" (random (expt 36 12) (make-random-state t))))
        (stream-channel nil) (transfer-channel nil) (sender nil) (failure nil))
    (unwind-protect
         (progn
           (setf stream-channel (make-unix-grpc-channel socket-path :timeout timeout))
           (let ((stream (ag-grpc:call-bidirectional-streaming
                          stream-channel "/containerd.services.streaming.v1.Streaming/Stream"
                          :metadata metadata :timeout timeout
                          :response-type 'gr8s.containerd.transfer.v1::any)))
             (ag-grpc:stream-send stream (containerd-any "containerd.services.streaming.v1.StreamInit"
                                                         (make-instance 'gr8s.containerd.transfer.v1::stream-init :id id)))
             ;; containerd answers once the stream is registered under ID.
             (unless (ag-grpc:stream-read-message stream)
               (error 'runtime-error :message "containerd did not register the image stream"))
             (setf sender
                   (bt:make-thread
                    (lambda ()
                      (handler-case
                          (with-open-file (input path :element-type '(unsigned-byte 8))
                            (send-image-archive input
                                                (lambda (message) (ag-grpc:stream-send stream message))
                                                (lambda () (ag-grpc:stream-read-message stream)))
                            (ag-grpc:stream-close-send stream))
                        (error (condition)
                          (setf failure condition)
                          ;; Breaking the stream fails the Transfer, which would otherwise wait for data.
                          (ignore-errors (ag-grpc:channel-close stream-channel)))))
                    :name "gr8s image archive sender"))
             (setf transfer-channel (make-unix-grpc-channel socket-path :timeout timeout))
             (let ((call (ag-grpc:call-unary
                          transfer-channel "/containerd.services.transfer.v1.Transfer/Transfer"
                          (make-instance
                           'gr8s.containerd.transfer.v1::transfer-request
                           :source (containerd-any "containerd.types.transfer.ImageImportStream"
                                                   (make-instance 'gr8s.containerd.transfer.v1::image-import-stream
                                                                  :stream id))
                           :destination (containerd-any "containerd.types.transfer.ImageStore"
                                                        (image-archive-import-store platform snapshotter))
                           :options (make-instance 'gr8s.containerd.transfer.v1::transfer-options))
                          :metadata metadata :timeout timeout
                          :response-type 'gr8s.containerd.transfer.v1::empty)))
               (ensure-cri-status "Transfer" (ag-grpc:call-status call)))
             (bt:join-thread sender)
             (setf sender nil)
             (when failure (error failure))))
      (when transfer-channel (ag-grpc:channel-close transfer-channel))
      (when stream-channel (ag-grpc:channel-close stream-channel))
      (when sender (ignore-errors (bt:join-thread sender))))))

(defun preload-managed-containerd-images (manager)
  "Import each archive in MANAGER's images directory, logging rather than failing on a bad one."
  (let ((archives (image-archive-paths (managed-containerd-images-directory manager))))
    (dolist (path archives)
      (let ((start (get-internal-real-time)))
        (handler-case
            (progn
              (import-image-archive (managed-containerd-socket-path manager) path
                                    :platform (managed-containerd-platform manager)
                                    :snapshotter (managed-containerd-snapshotter manager))
              (format *error-output* "gr8s imported image archive ~A in ~,1Fs~%" (namestring path)
                      (/ (- (get-internal-real-time) start) internal-time-units-per-second)))
          (error (condition)
            (format *error-output* "gr8s could not import image archive ~A: ~A~%" (namestring path) condition)))
        (finish-output *error-output*)))
    (length archives)))
