;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Package definitions shared by generated protobuf bindings and their
;;;; standalone generators. Keep the shadow lists synchronized with the
;;;; generated message and field names.

(defpackage #:gr8s.cri.v1
  (:use #:cl)
  (:shadow #:labels #:some))

(defpackage #:gr8s.csi.v1
  (:use #:cl)
  (:shadow #:type #:labels #:some #:block))

(defpackage #:gr8s.pluginregistration.v1
  (:use #:cl)
  (:shadow #:type #:block))

(defpackage #:gr8s.dra.v1
  (:use #:cl)
  (:shadow #:block))

(defpackage #:gr8s.deviceplugin.v1beta1
  (:use #:cl))

(defpackage #:gr8s.podresources.v1
  (:use #:cl))

(defpackage #:gr8s.containerd.tasks.v1
  (:use #:cl)
  (:shadow #:signal))

(defpackage #:gr8s.containerd.transfer.v1
  (:use #:cl))

(defpackage #:gr8s.node.v1
  (:use #:cl)
  (:shadow #:labels #:phase))
