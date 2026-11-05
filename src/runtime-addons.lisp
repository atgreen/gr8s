;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Optional runtime payloads (epic podster-mgw). A runtime addon is an
;;;; out-of-image, checksum-verified set of binaries (e.g. a gVisor runsc shim)
;;;; installed under <state-dir>/runtime-addons/<name>/ with an addon.json
;;;; descriptor. At startup the managed containerd picks up every valid addon as
;;;; an extra CRI runtime handler, so the base image stays lean and runtimes are
;;;; delivered and pinned separately. A bad addon (missing descriptor, checksum
;;;; mismatch) is skipped with a warning; it never silently changes the runtime
;;;; or blocks the node from starting.

(in-package #:gr8s)

(defun runtime-addons-directory (state-directory)
  "The directory holding installed runtime addons for this node."
  (merge-pathnames "runtime-addons/"
                   (uiop:ensure-directory-pathname state-directory)))

(defun runtime-addon-file-sha512 (path)
  "Lowercase hex SHA-512 of PATH's contents."
  (ironclad:byte-array-to-hex-string (ironclad:digest-file :sha512 path)))

(defun runtime-addon-binary-verified-p (addon-directory binary)
  "True when BINARY (a hash-table with \"path\" and \"sha512\") exists under
   ADDON-DIRECTORY and its contents match the pinned checksum."
  (let* ((relative (gethash "path" binary))
         (expected (gethash "sha512" binary)))
    (and (stringp relative) (plusp (length relative))
         (stringp expected) (plusp (length expected))
         ;; Keep the binary inside the addon directory: reject absolute paths
         ;; and any "..ends up outside" traversal before touching the file.
         (not (uiop:absolute-pathname-p relative))
         (let ((file (merge-pathnames relative addon-directory)))
           (and (uiop:subpathp file addon-directory)
                (probe-file file)
                (string-equal expected (runtime-addon-file-sha512 file)))))))

(defun parse-runtime-addon-descriptor (object)
  "Validate an addon.json OBJECT (a jzon hash-table) into a plist
   (:name :runtime-type :runtime-class :binaries). Signals on a structural
   problem so the caller can skip this addon."
  (let ((name (gethash "name" object))
        (runtime-type (gethash "runtimeType" object))
        (runtime-class (gethash "runtimeClass" object))
        (binaries (gethash "binaries" object)))
    (unless (and (stringp name) (plusp (length name)))
      (error "runtime addon descriptor is missing a name"))
    (unless (and (stringp runtime-type) (plusp (length runtime-type)))
      (error "runtime addon ~A is missing runtimeType" name))
    (list :name name
          :runtime-type runtime-type
          :runtime-class (if (and (stringp runtime-class) (plusp (length runtime-class)))
                             runtime-class
                             name)
          :binaries (coerce (or binaries #()) 'list))))

(defun load-runtime-addon (addon-directory)
  "Load and verify the addon in ADDON-DIRECTORY. Return an extra-runtime-handler
   plist (:name :runtime-type :options) for a valid addon, or NIL (warning) when
   its descriptor is missing/invalid or any binary fails its checksum."
  (let ((descriptor (merge-pathnames "addon.json" addon-directory)))
    (unless (probe-file descriptor)
      (return-from load-runtime-addon nil))
    (handler-case
        (let* ((object (com.inuoe.jzon:parse (uiop:read-file-string descriptor)))
               (addon (parse-runtime-addon-descriptor object)))
          (if (every (lambda (binary)
                       (runtime-addon-binary-verified-p addon-directory binary))
                     (getf addon :binaries))
              ;; runsc-style handlers need only runtime_type; options stay empty.
              ;; :bin-dir is carried so the managed containerd can add it to the
              ;; shim PATH (containerd execs the shim binary by name); the config
              ;; emitter ignores keys beyond :name/:runtime-type/:options.
              (list :name (getf addon :name)
                    :runtime-type (getf addon :runtime-type)
                    :options nil
                    :bin-dir (namestring (uiop:ensure-directory-pathname addon-directory)))
              (progn
                (warn "runtime addon ~A: a binary failed its checksum; skipping"
                      (getf addon :name))
                nil)))
      (error (condition)
        (warn "runtime addon ~A: ~A; skipping"
              (namestring addon-directory) condition)
        nil))))

(defun load-installed-runtime-addons (state-directory)
  "Return extra-runtime-handler plists for every valid addon installed under
   STATE-DIRECTORY, in stable name order. Safe when the directory is absent."
  (let ((root (runtime-addons-directory state-directory)))
    (when (uiop:directory-exists-p root)
      (loop for addon-directory in (sort (uiop:subdirectories root) #'string<
                                         :key #'namestring)
            for handler = (load-runtime-addon addon-directory)
            when handler collect handler))))
