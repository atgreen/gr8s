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

(defun runtime-addon-file-verified-p (addon-directory file)
  "True when FILE (a hash-table with \"path\" and \"sha512\") exists under
   ADDON-DIRECTORY and its contents match the pinned checksum. Used for both
   executable binaries and non-executable data assets (guest kernel, rootfs)."
  (let* ((relative (gethash "path" file))
         (expected (gethash "sha512" file)))
    (and (stringp relative) (plusp (length relative))
         (stringp expected) (plusp (length expected))
         ;; Keep the binary inside the addon directory: reject absolute paths
         ;; and any "..ends up outside" traversal before touching the file.
         (not (uiop:absolute-pathname-p relative))
         (let ((file (merge-pathnames relative addon-directory)))
           (and (uiop:subpathp file addon-directory)
                (probe-file file)
                (string-equal expected (runtime-addon-file-sha512 file)))))))

(defun runtime-addon-option-toml-scalar (value)
  "Render a JSON option VALUE (as produced by jzon) into the already-quoted TOML
   scalar the managed containerd config emitter expects. Only scalars map: a
   string becomes a single-quoted TOML literal, a boolean becomes true/false, a
   number prints bare. Anything else -- including JSON null, an array, or a
   nested object -- signals, so a malformed option skips the addon instead of
   emitting broken TOML. A string that cannot be a TOML literal (it contains a
   single quote, a newline, or a control character) signals for the same reason."
  (cond
    ((eq value t) "true")
    ((null value) "false")              ; jzon parses JSON false to NIL
    ((integerp value) (format nil "~D" value))
    ((floatp value) (format nil "~F" value))
    ((stringp value)
     (when (or (find #\' value)
               (find #\Newline value)
               (some (lambda (character) (< (char-code character) 32)) value))
       (error "runtime addon option string ~S cannot be a TOML literal" value))
     (format nil "'~A'" value))
    (t (error "runtime addon option value ~S is not a TOML scalar" value))))

(defun parse-runtime-addon-options (object)
  "Return the optional \"options\" map of addon descriptor OBJECT as a
   deterministic alist of (KEY . TOML-SCALAR), sorted by key for stable config
   output, or NIL when absent. Signals on a non-object options value, a
   non-string key, or a non-scalar option value."
  (let ((options (gethash "options" object)))
    (when options
      (unless (hash-table-p options)
        (error "runtime addon options must be a JSON object"))
      (let ((pairs '()))
        (maphash (lambda (key value)
                   (unless (stringp key)
                     (error "runtime addon option key ~S must be a string" key))
                   (push (cons key (runtime-addon-option-toml-scalar value)) pairs))
                 options)
        (sort pairs #'string< :key #'car)))))

(defun parse-runtime-addon-descriptor (object)
  "Validate an addon.json OBJECT (a jzon hash-table) into a plist
   (:name :runtime-type :runtime-class :binaries :options). Signals on a
   structural problem so the caller can skip this addon."
  (let ((name (gethash "name" object))
        (runtime-type (gethash "runtimeType" object))
        (runtime-class (gethash "runtimeClass" object))
        (binaries (gethash "binaries" object))
        (assets (gethash "assets" object)))
    (unless (and (stringp name) (plusp (length name)))
      (error "runtime addon descriptor is missing a name"))
    (unless (and (stringp runtime-type) (plusp (length runtime-type)))
      (error "runtime addon ~A is missing runtimeType" name))
    (list :name name
          :runtime-type runtime-type
          :runtime-class (if (and (stringp runtime-class) (plusp (length runtime-class)))
                             runtime-class
                             name)
          :binaries (coerce (or binaries #()) 'list)
          :assets (coerce (or assets #()) 'list)
          :options (parse-runtime-addon-options object))))

(defun load-runtime-addon (addon-directory)
  "Load and verify the addon in ADDON-DIRECTORY. Return an extra-runtime-handler
   plist (:name :runtime-type :options) for a valid addon, or NIL (warning) when
   its descriptor is missing/invalid or any binary or asset fails its checksum."
  (let ((descriptor (merge-pathnames "addon.json" addon-directory)))
    (unless (probe-file descriptor)
      (return-from load-runtime-addon nil))
    (handler-case
        (let* ((object (com.inuoe.jzon:parse (uiop:read-file-string descriptor)))
               (addon (parse-runtime-addon-descriptor object)))
          (if (every (lambda (file)
                       (runtime-addon-file-verified-p addon-directory file))
                     (append (getf addon :binaries) (getf addon :assets)))
              ;; runsc-style handlers carry no options; microVM shims (e.g. Kata)
              ;; carry a ConfigPath and friends via the descriptor's "options".
              ;; :bin-dir is carried so the managed containerd can add it to the
              ;; shim PATH (containerd execs the shim binary by name); the config
              ;; emitter ignores keys beyond :name/:runtime-type/:options.
              (list :name (getf addon :name)
                    :runtime-type (getf addon :runtime-type)
                    :options (getf addon :options)
                    :bin-dir (namestring (uiop:ensure-directory-pathname addon-directory)))
              (progn
                (warn "runtime addon ~A: a binary or asset failed its checksum; skipping"
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
