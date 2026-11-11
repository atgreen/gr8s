;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Encode the standard BitTorrent peer wire used by private OCI blob swarms.

(in-package #:gr8s.image-distribution)

(defparameter +peer-protocol-name+ "BitTorrent protocol")
(defconstant +peer-handshake-length+ 68)
(defconstant +peer-block-length+ 16384)
(defconstant +maximum-peer-message-length+ (+ 9 +peer-block-length+))

(defun put-u32 (octets offset value)
  (unless (typep value '(unsigned-byte 32))
    (error "BitTorrent integer is outside the uint32 range"))
  (setf (aref octets offset) (ldb (byte 8 24) value)
        (aref octets (+ offset 1)) (ldb (byte 8 16) value)
        (aref octets (+ offset 2)) (ldb (byte 8 8) value)
        (aref octets (+ offset 3)) (ldb (byte 8 0) value))
  octets)

(defun get-u32 (octets offset)
  (when (> (+ offset 4) (length octets))
    (error "Truncated BitTorrent uint32"))
  (logior (ash (aref octets offset) 24)
          (ash (aref octets (+ offset 1)) 16)
          (ash (aref octets (+ offset 2)) 8)
          (aref octets (+ offset 3))))

(defun require-peer-id (peer-id)
  (unless (and (typep peer-id '(vector (unsigned-byte 8)))
               (= 20 (length peer-id)))
    (error "A BitTorrent peer id must contain exactly 20 octets")))

(defun peer-message-id (kind)
  (ecase kind
    (:choke 0) (:unchoke 1) (:interested 2) (:not-interested 3)
    (:have 4) (:bitfield 5) (:request 6) (:piece 7) (:cancel 8)))

(defun validate-block-request (message)
  (unless (and (typep (peer-message-length message)
                      `(integer 1 ,+peer-block-length+))
               (typep (peer-message-piece message) '(unsigned-byte 32))
               (typep (peer-message-begin message) '(unsigned-byte 32)))
    (error "Invalid BitTorrent block request")))

(defun rarest-missing-piece (completed availability peer-bitfield)
  "Choose the rarest piece this peer has, breaking ties by lowest index."
  (unless (= (length completed) (length availability) (length peer-bitfield))
    (error "Piece selection vectors must have equal lengths"))
  (loop with selected = nil and selected-count = nil
        for index below (length completed)
        for count = (aref availability index)
        when (and (not (member (aref completed index) '(t 1)))
                  (aref peer-bitfield index)
                  (plusp count)
                  (or (null selected-count) (< count selected-count)))
          do (setf selected index selected-count count)
        finally (return selected)))

(defun read-exactly (stream length &key eof-ok)
  (let ((result (make-array length :element-type '(unsigned-byte 8)))
        (offset 0))
    (loop while (< offset length)
          for count = (read-sequence result stream :start offset)
          do (when (= count offset)
               (if (and eof-ok (zerop offset))
                   (return-from read-exactly nil)
                   (error "Peer closed a partial BitTorrent frame")))
             (setf offset count))
    result))

(defun write-peer-handshake (stream infohash peer-id)
  (write-sequence (encode-peer-handshake infohash peer-id) stream)
  (finish-output stream))

(defun read-peer-handshake (stream)
  (decode-peer-handshake (read-exactly stream +peer-handshake-length+)))

(defun write-peer-message (stream message)
  (write-sequence (encode-peer-message message) stream)
  (finish-output stream))

(defun read-peer-message (stream &key eof-ok)
  (let ((prefix (read-exactly stream 4 :eof-ok eof-ok)))
    (when prefix
      (let ((length (get-u32 prefix 0)))
        (when (> length +maximum-peer-message-length+)
          (error "BitTorrent peer message exceeds the configured bound"))
        (decode-peer-message
         (concatenate '(vector (unsigned-byte 8))
                      prefix (read-exactly stream length)))))))

(defun piece-vector-to-bitfield (pieces)
  (let ((result (make-array (ceiling (length pieces) 8)
                            :element-type '(unsigned-byte 8)
                            :initial-element 0)))
    (loop for piece below (length pieces)
          when (member (aref pieces piece) '(t 1))
            do (setf (ldb (byte 1 (- 7 (mod piece 8)))
                          (aref result (floor piece 8)))
                     1))
    result))

(defun bitfield-to-piece-vector (bitfield piece-count)
  (let ((result (make-array piece-count :element-type 'bit :initial-element 0)))
    (loop for piece below piece-count
          when (and (< (floor piece 8) (length bitfield))
                    (= 1 (ldb (byte 1 (- 7 (mod piece 8)))
                              (aref bitfield (floor piece 8)))))
            do (setf (aref result piece) 1))
    result))

(defun ensure-handshake-swarm (handshake torrent)
  (unless (equalp (peer-handshake-infohash handshake)
                  (subseq (torrent-infohash torrent) 0 20))
    (error "Peer attempted to join the wrong BitTorrent swarm")))

(defun read-file-block (pathname torrent piece begin length)
  (let ((piece-size (torrent-piece-size torrent piece)))
    (unless (and (< piece (torrent-piece-count torrent))
                 (<= 0 begin) (<= (+ begin length) piece-size)
                 (<= 1 length +peer-block-length+))
      (error "Peer requested a block outside the OCI blob"))
    (with-open-file (stream pathname :direction :input
                                     :element-type '(unsigned-byte 8))
      (file-position stream (+ (* piece (torrent-piece-length torrent)) begin))
      (read-exactly stream length))))

(defun serve-peer-stream (stream torrent pathname peer-id completed &key handshake)
  "Serve verified pieces over one already-authenticated peer stream."
  (let ((handshake (or handshake (read-peer-handshake stream))))
    (ensure-handshake-swarm handshake torrent)
    (write-peer-handshake stream (torrent-infohash torrent) peer-id)
    (write-peer-message
     stream (make-peer-message :kind :bitfield
                               :payload (piece-vector-to-bitfield completed)))
    (write-peer-message stream (make-peer-message :kind :unchoke))
    (loop for message = (read-peer-message stream :eof-ok t)
          while message
          do (case (peer-message-kind message)
               (:request
                (let ((piece (peer-message-piece message)))
                  (unless (and (< piece (length completed))
                               (member (aref completed piece) '(t 1)))
                    (error "Peer requested an unverified piece"))
                  (write-peer-message
                   stream
                   (make-peer-message
                    :kind :piece :piece piece :begin (peer-message-begin message)
                    :payload (read-file-block
                              pathname torrent piece (peer-message-begin message)
                              (peer-message-length message))))))
               ((:interested :not-interested :cancel :keepalive))
               (otherwise
                (error "Unexpected downloader message ~S"
                       (peer-message-kind message)))))))

(define-condition corrupt-peer-piece (error)
  ((piece :initarg :piece :reader corrupt-peer-piece-index))
  (:report (lambda (condition stream)
             (format stream "Peer supplied corrupt BitTorrent piece ~D"
                     (corrupt-peer-piece-index condition)))))

(defun missing-peer-blocks (torrent store peer-pieces)
  (let ((completed (completed-pieces store)))
    (loop for piece below (length completed)
          when (and (zerop (aref completed piece))
                    (= 1 (aref peer-pieces piece)))
            append (loop for begin from 0 below (torrent-piece-size torrent piece)
                         by +peer-block-length+
                         collect (list piece begin
                                       (min +peer-block-length+
                                            (- (torrent-piece-size torrent piece) begin)))))))

(defun download-from-peer-stream
    (stream torrent store peer-id &key (pipeline-depth 8))
  "Download all missing pieces available from one authenticated peer."
  (unless (typep pipeline-depth '(integer 1 128))
    (error "BitTorrent pipeline depth must be between 1 and 128"))
  (write-peer-handshake stream (torrent-infohash torrent) peer-id)
  (ensure-handshake-swarm (read-peer-handshake stream) torrent)
  (let ((peer-pieces nil) (choked-p t) (pending nil) (remaining nil))
    (write-peer-message stream (make-peer-message :kind :interested))
    (loop until (and peer-pieces (not choked-p))
          for message = (read-peer-message stream)
          do (case (peer-message-kind message)
               (:bitfield
                (setf peer-pieces
                      (bitfield-to-piece-vector
                       (peer-message-payload message)
                       (torrent-piece-count torrent))))
               (:unchoke (setf choked-p nil))
               (:choke (setf choked-p t))))
    (setf remaining (missing-peer-blocks torrent store peer-pieces))
    (loop while (or remaining pending)
          do (loop while (and remaining (not choked-p)
                              (< (length pending) pipeline-depth))
                   for request = (pop remaining)
                   do (write-peer-message
                       stream (make-peer-message
                               :kind :request :piece (first request)
                               :begin (second request) :length (third request)))
                      (setf pending (nconc pending (list request))))
             (let ((message (read-peer-message stream)))
               (case (peer-message-kind message)
                 (:piece
                  (let* ((key (list (peer-message-piece message)
                                    (peer-message-begin message)
                                    (length (peer-message-payload message))))
                         (request (find key pending :test #'equal)))
                    (unless request (error "Peer sent an unrequested piece block"))
                    (setf pending (delete request pending :test #'eq))
                    (when (eq :corrupt
                              (accept-block
                               store (first key) (second key)
                               (peer-message-payload message)))
                      (error 'corrupt-peer-piece :piece (first key)))))
                 (:choke (setf choked-p t))
                 (:unchoke (setf choked-p nil))
                 (:have (setf (aref peer-pieces (peer-message-piece message)) 1))
                 (:keepalive)
                 (otherwise
                  (error "Unexpected seeder message ~S"
                         (peer-message-kind message))))))
    (write-peer-message stream (make-peer-message :kind :not-interested))
    (piece-store-complete-p store)))
