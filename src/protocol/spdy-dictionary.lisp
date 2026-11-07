;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; The fixed zlib dictionary SPDY/3 compresses header blocks against, as the
;;;; SPDY/3 specification defines it. Its Adler-32 is the identifier in
;;;; +SPDY-ZLIB-HEADER+.

(in-package #:gr8s.protocol)

(defparameter +spdy-header-dictionary+
  (coerce
   '(#x00 #x00 #x00 #x07 #x6F #x70 #x74 #x69 #x6F #x6E #x73 #x00 #x00 #x00 #x04 #x68
     #x65 #x61 #x64 #x00 #x00 #x00 #x04 #x70 #x6F #x73 #x74 #x00 #x00 #x00 #x03 #x70
     #x75 #x74 #x00 #x00 #x00 #x06 #x64 #x65 #x6C #x65 #x74 #x65 #x00 #x00 #x00 #x05
     #x74 #x72 #x61 #x63 #x65 #x00 #x00 #x00 #x06 #x61 #x63 #x63 #x65 #x70 #x74 #x00
     #x00 #x00 #x0E #x61 #x63 #x63 #x65 #x70 #x74 #x2D #x63 #x68 #x61 #x72 #x73 #x65
     #x74 #x00 #x00 #x00 #x0F #x61 #x63 #x63 #x65 #x70 #x74 #x2D #x65 #x6E #x63 #x6F
     #x64 #x69 #x6E #x67 #x00 #x00 #x00 #x0F #x61 #x63 #x63 #x65 #x70 #x74 #x2D #x6C
     #x61 #x6E #x67 #x75 #x61 #x67 #x65 #x00 #x00 #x00 #x0D #x61 #x63 #x63 #x65 #x70
     #x74 #x2D #x72 #x61 #x6E #x67 #x65 #x73 #x00 #x00 #x00 #x03 #x61 #x67 #x65 #x00
     #x00 #x00 #x05 #x61 #x6C #x6C #x6F #x77 #x00 #x00 #x00 #x0D #x61 #x75 #x74 #x68
     #x6F #x72 #x69 #x7A #x61 #x74 #x69 #x6F #x6E #x00 #x00 #x00 #x0D #x63 #x61 #x63
     #x68 #x65 #x2D #x63 #x6F #x6E #x74 #x72 #x6F #x6C #x00 #x00 #x00 #x0A #x63 #x6F
     #x6E #x6E #x65 #x63 #x74 #x69 #x6F #x6E #x00 #x00 #x00 #x0C #x63 #x6F #x6E #x74
     #x65 #x6E #x74 #x2D #x62 #x61 #x73 #x65 #x00 #x00 #x00 #x10 #x63 #x6F #x6E #x74
     #x65 #x6E #x74 #x2D #x65 #x6E #x63 #x6F #x64 #x69 #x6E #x67 #x00 #x00 #x00 #x10
     #x63 #x6F #x6E #x74 #x65 #x6E #x74 #x2D #x6C #x61 #x6E #x67 #x75 #x61 #x67 #x65
     #x00 #x00 #x00 #x0E #x63 #x6F #x6E #x74 #x65 #x6E #x74 #x2D #x6C #x65 #x6E #x67
     #x74 #x68 #x00 #x00 #x00 #x10 #x63 #x6F #x6E #x74 #x65 #x6E #x74 #x2D #x6C #x6F
     #x63 #x61 #x74 #x69 #x6F #x6E #x00 #x00 #x00 #x0B #x63 #x6F #x6E #x74 #x65 #x6E
     #x74 #x2D #x6D #x64 #x35 #x00 #x00 #x00 #x0D #x63 #x6F #x6E #x74 #x65 #x6E #x74
     #x2D #x72 #x61 #x6E #x67 #x65 #x00 #x00 #x00 #x0C #x63 #x6F #x6E #x74 #x65 #x6E
     #x74 #x2D #x74 #x79 #x70 #x65 #x00 #x00 #x00 #x04 #x64 #x61 #x74 #x65 #x00 #x00
     #x00 #x04 #x65 #x74 #x61 #x67 #x00 #x00 #x00 #x06 #x65 #x78 #x70 #x65 #x63 #x74
     #x00 #x00 #x00 #x07 #x65 #x78 #x70 #x69 #x72 #x65 #x73 #x00 #x00 #x00 #x04 #x66
     #x72 #x6F #x6D #x00 #x00 #x00 #x04 #x68 #x6F #x73 #x74 #x00 #x00 #x00 #x08 #x69
     #x66 #x2D #x6D #x61 #x74 #x63 #x68 #x00 #x00 #x00 #x11 #x69 #x66 #x2D #x6D #x6F
     #x64 #x69 #x66 #x69 #x65 #x64 #x2D #x73 #x69 #x6E #x63 #x65 #x00 #x00 #x00 #x0D
     #x69 #x66 #x2D #x6E #x6F #x6E #x65 #x2D #x6D #x61 #x74 #x63 #x68 #x00 #x00 #x00
     #x08 #x69 #x66 #x2D #x72 #x61 #x6E #x67 #x65 #x00 #x00 #x00 #x13 #x69 #x66 #x2D
     #x75 #x6E #x6D #x6F #x64 #x69 #x66 #x69 #x65 #x64 #x2D #x73 #x69 #x6E #x63 #x65
     #x00 #x00 #x00 #x0D #x6C #x61 #x73 #x74 #x2D #x6D #x6F #x64 #x69 #x66 #x69 #x65
     #x64 #x00 #x00 #x00 #x08 #x6C #x6F #x63 #x61 #x74 #x69 #x6F #x6E #x00 #x00 #x00
     #x0C #x6D #x61 #x78 #x2D #x66 #x6F #x72 #x77 #x61 #x72 #x64 #x73 #x00 #x00 #x00
     #x06 #x70 #x72 #x61 #x67 #x6D #x61 #x00 #x00 #x00 #x12 #x70 #x72 #x6F #x78 #x79
     #x2D #x61 #x75 #x74 #x68 #x65 #x6E #x74 #x69 #x63 #x61 #x74 #x65 #x00 #x00 #x00
     #x13 #x70 #x72 #x6F #x78 #x79 #x2D #x61 #x75 #x74 #x68 #x6F #x72 #x69 #x7A #x61
     #x74 #x69 #x6F #x6E #x00 #x00 #x00 #x05 #x72 #x61 #x6E #x67 #x65 #x00 #x00 #x00
     #x07 #x72 #x65 #x66 #x65 #x72 #x65 #x72 #x00 #x00 #x00 #x0B #x72 #x65 #x74 #x72
     #x79 #x2D #x61 #x66 #x74 #x65 #x72 #x00 #x00 #x00 #x06 #x73 #x65 #x72 #x76 #x65
     #x72 #x00 #x00 #x00 #x02 #x74 #x65 #x00 #x00 #x00 #x07 #x74 #x72 #x61 #x69 #x6C
     #x65 #x72 #x00 #x00 #x00 #x11 #x74 #x72 #x61 #x6E #x73 #x66 #x65 #x72 #x2D #x65
     #x6E #x63 #x6F #x64 #x69 #x6E #x67 #x00 #x00 #x00 #x07 #x75 #x70 #x67 #x72 #x61
     #x64 #x65 #x00 #x00 #x00 #x0A #x75 #x73 #x65 #x72 #x2D #x61 #x67 #x65 #x6E #x74
     #x00 #x00 #x00 #x04 #x76 #x61 #x72 #x79 #x00 #x00 #x00 #x03 #x76 #x69 #x61 #x00
     #x00 #x00 #x07 #x77 #x61 #x72 #x6E #x69 #x6E #x67 #x00 #x00 #x00 #x10 #x77 #x77
     #x77 #x2D #x61 #x75 #x74 #x68 #x65 #x6E #x74 #x69 #x63 #x61 #x74 #x65 #x00 #x00
     #x00 #x06 #x6D #x65 #x74 #x68 #x6F #x64 #x00 #x00 #x00 #x03 #x67 #x65 #x74 #x00
     #x00 #x00 #x06 #x73 #x74 #x61 #x74 #x75 #x73 #x00 #x00 #x00 #x06 #x32 #x30 #x30
     #x20 #x4F #x4B #x00 #x00 #x00 #x07 #x76 #x65 #x72 #x73 #x69 #x6F #x6E #x00 #x00
     #x00 #x08 #x48 #x54 #x54 #x50 #x2F #x31 #x2E #x31 #x00 #x00 #x00 #x03 #x75 #x72
     #x6C #x00 #x00 #x00 #x06 #x70 #x75 #x62 #x6C #x69 #x63 #x00 #x00 #x00 #x0A #x73
     #x65 #x74 #x2D #x63 #x6F #x6F #x6B #x69 #x65 #x00 #x00 #x00 #x0A #x6B #x65 #x65
     #x70 #x2D #x61 #x6C #x69 #x76 #x65 #x00 #x00 #x00 #x06 #x6F #x72 #x69 #x67 #x69
     #x6E #x31 #x30 #x30 #x31 #x30 #x31 #x32 #x30 #x31 #x32 #x30 #x32 #x32 #x30 #x35
     #x32 #x30 #x36 #x33 #x30 #x30 #x33 #x30 #x32 #x33 #x30 #x33 #x33 #x30 #x34 #x33
     #x30 #x35 #x33 #x30 #x36 #x33 #x30 #x37 #x34 #x30 #x32 #x34 #x30 #x35 #x34 #x30
     #x36 #x34 #x30 #x37 #x34 #x30 #x38 #x34 #x30 #x39 #x34 #x31 #x30 #x34 #x31 #x31
     #x34 #x31 #x32 #x34 #x31 #x33 #x34 #x31 #x34 #x34 #x31 #x35 #x34 #x31 #x36 #x34
     #x31 #x37 #x35 #x30 #x32 #x35 #x30 #x34 #x35 #x30 #x35 #x32 #x30 #x33 #x20 #x4E
     #x6F #x6E #x2D #x41 #x75 #x74 #x68 #x6F #x72 #x69 #x74 #x61 #x74 #x69 #x76 #x65
     #x20 #x49 #x6E #x66 #x6F #x72 #x6D #x61 #x74 #x69 #x6F #x6E #x32 #x30 #x34 #x20
     #x4E #x6F #x20 #x43 #x6F #x6E #x74 #x65 #x6E #x74 #x33 #x30 #x31 #x20 #x4D #x6F
     #x76 #x65 #x64 #x20 #x50 #x65 #x72 #x6D #x61 #x6E #x65 #x6E #x74 #x6C #x79 #x34
     #x30 #x30 #x20 #x42 #x61 #x64 #x20 #x52 #x65 #x71 #x75 #x65 #x73 #x74 #x34 #x30
     #x31 #x20 #x55 #x6E #x61 #x75 #x74 #x68 #x6F #x72 #x69 #x7A #x65 #x64 #x34 #x30
     #x33 #x20 #x46 #x6F #x72 #x62 #x69 #x64 #x64 #x65 #x6E #x34 #x30 #x34 #x20 #x4E
     #x6F #x74 #x20 #x46 #x6F #x75 #x6E #x64 #x35 #x30 #x30 #x20 #x49 #x6E #x74 #x65
     #x72 #x6E #x61 #x6C #x20 #x53 #x65 #x72 #x76 #x65 #x72 #x20 #x45 #x72 #x72 #x6F
     #x72 #x35 #x30 #x31 #x20 #x4E #x6F #x74 #x20 #x49 #x6D #x70 #x6C #x65 #x6D #x65
     #x6E #x74 #x65 #x64 #x35 #x30 #x33 #x20 #x53 #x65 #x72 #x76 #x69 #x63 #x65 #x20
     #x55 #x6E #x61 #x76 #x61 #x69 #x6C #x61 #x62 #x6C #x65 #x4A #x61 #x6E #x20 #x46
     #x65 #x62 #x20 #x4D #x61 #x72 #x20 #x41 #x70 #x72 #x20 #x4D #x61 #x79 #x20 #x4A
     #x75 #x6E #x20 #x4A #x75 #x6C #x20 #x41 #x75 #x67 #x20 #x53 #x65 #x70 #x74 #x20
     #x4F #x63 #x74 #x20 #x4E #x6F #x76 #x20 #x44 #x65 #x63 #x20 #x30 #x30 #x3A #x30
     #x30 #x3A #x30 #x30 #x20 #x4D #x6F #x6E #x2C #x20 #x54 #x75 #x65 #x2C #x20 #x57
     #x65 #x64 #x2C #x20 #x54 #x68 #x75 #x2C #x20 #x46 #x72 #x69 #x2C #x20 #x53 #x61
     #x74 #x2C #x20 #x53 #x75 #x6E #x2C #x20 #x47 #x4D #x54 #x63 #x68 #x75 #x6E #x6B
     #x65 #x64 #x2C #x74 #x65 #x78 #x74 #x2F #x68 #x74 #x6D #x6C #x2C #x69 #x6D #x61
     #x67 #x65 #x2F #x70 #x6E #x67 #x2C #x69 #x6D #x61 #x67 #x65 #x2F #x6A #x70 #x67
     #x2C #x69 #x6D #x61 #x67 #x65 #x2F #x67 #x69 #x66 #x2C #x61 #x70 #x70 #x6C #x69
     #x63 #x61 #x74 #x69 #x6F #x6E #x2F #x78 #x6D #x6C #x2C #x61 #x70 #x70 #x6C #x69
     #x63 #x61 #x74 #x69 #x6F #x6E #x2F #x78 #x68 #x74 #x6D #x6C #x2B #x78 #x6D #x6C
     #x2C #x74 #x65 #x78 #x74 #x2F #x70 #x6C #x61 #x69 #x6E #x2C #x74 #x65 #x78 #x74
     #x2F #x6A #x61 #x76 #x61 #x73 #x63 #x72 #x69 #x70 #x74 #x2C #x70 #x75 #x62 #x6C
     #x69 #x63 #x70 #x72 #x69 #x76 #x61 #x74 #x65 #x6D #x61 #x78 #x2D #x61 #x67 #x65
     #x3D #x67 #x7A #x69 #x70 #x2C #x64 #x65 #x66 #x6C #x61 #x74 #x65 #x2C #x73 #x64
     #x63 #x68 #x63 #x68 #x61 #x72 #x73 #x65 #x74 #x3D #x75 #x74 #x66 #x2D #x38 #x63
     #x68 #x61 #x72 #x73 #x65 #x74 #x3D #x69 #x73 #x6F #x2D #x38 #x38 #x35 #x39 #x2D
     #x31 #x2C #x75 #x74 #x66 #x2D #x2C #x2A #x2C #x65 #x6E #x71 #x3D #x30 #x2E)
   '(simple-array (unsigned-byte 8) (*))))

