;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Package boundary for `gr8s upgrade': gr8s release packages kept as signed OCI
;;;; artifacts, the host installer that puts one in place, and the planner that
;;;; orders a cluster's hosts for a rolling upgrade.

(defpackage #:gr8s.upgrade
  (:use #:cl)
  (:export
   #:+gr8s-format-level+
   #:+release-artifact-type+
   #:cluster-format-level-allows-p
   #:compare-gr8s-versions
   #:gr8s-version
   #:gr8s-version-dev-p
   #:parse-gr8s-version
   #:release-key
   #:release-key-id
   #:read-release-signing-key
   #:release-artifact
   #:release-artifact-version
   #:release-artifact-packages
   #:release-artifact-digest
   #:fetch-release-artifact
   #:publish-release-artifact
   #:mirror-release-artifact
   #:parse-artifact-reference
   #:host-package-format
   #:prepare-host-upgrade
   #:install-host-upgrade
   #:run-host-upgrade
   #:upgrade-error
   #:plan-cluster-upgrade))
