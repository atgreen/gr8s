;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; One `gr8s dashboard' for both of gr8s's web UIs (podster-d33): a small page
;;;; with a Headlamp tab and a Hubble tab, each the app gr8s already serves, in a
;;;; same-origin frame. One loopback server and one unguessable session token cover
;;;; all three: the page at /ui/<token>/, Headlamp at /dashboard/<token>/ and Hubble
;;;; UI at /hubble/<token>/. Each frame keeps its state while the other tab is
;;;; showing, and Hubble's is loaded only once its tab is first opened, so its
;;;; streams don't run for a reader who never looks at flows. The cluster's
;;;; DashboardTabs add tabs for its own apps, each from an origin of its own.

(in-package #:gr8s.server)

(defparameter +dashboard-shell-html+
  "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>gr8s dashboard</title>
<style>
:root { --bar: #f6f7f9; --line: #d9dde3; --text: #39414c; --muted: #6b7481; --accent: #1f6feb; }
@media (prefers-color-scheme: dark) {
  :root { --bar: #1d2026; --line: #343a44; --text: #d6dae0; --muted: #9aa3ae; --accent: #58a6ff; }
}
html, body { margin: 0; height: 100%; background: var(--bar); color: var(--text);
  font: 14px/1.4 system-ui, -apple-system, \"Segoe UI\", sans-serif; }
body { display: flex; flex-direction: column; }
nav { display: flex; align-items: stretch; gap: 4px; padding: 0 12px; height: 40px;
  border-bottom: 1px solid var(--line); flex: none; }
nav .name { align-self: center; font-weight: 600; margin-right: 12px; }
nav button { border: 0; background: none; color: var(--muted); font: inherit; padding: 0 12px;
  cursor: pointer; border-bottom: 2px solid transparent; }
nav button[aria-selected=\"true\"] { color: var(--text); border-bottom-color: var(--accent); }
nav button:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
main { flex: 1; position: relative; }
iframe { position: absolute; inset: 0; width: 100%; height: 100%; border: 0; background: #fff; }
iframe[hidden] { display: none; }
</style>
</head>
<body>
<nav role=\"tablist\" aria-label=\"gr8s dashboard\">
  <span class=\"name\">gr8s</span>
  ~:{<button role=\"tab\" id=\"tab-~A\" aria-controls=\"frame-~:*~A\" data-src=\"~A\">~A</button>~}
</nav>
<main>
  ~:{<iframe id=\"frame-~A\" title=\"~A\" referrerpolicy=\"no-referrer\" hidden></iframe>~}
</main>
<script>
const tabs = [...document.querySelectorAll('[role=tab]')];
function show(name) {
  const tab = tabs.find(t => t.id === 'tab-' + name) || tabs[0];
  for (const t of tabs) {
    const on = t === tab;
    const frame = document.getElementById(t.getAttribute('aria-controls'));
    t.setAttribute('aria-selected', on);
    frame.hidden = !on;
    // Load a tab's app the first time it is shown, then keep it.
    if (on && !frame.src) frame.src = t.dataset.src;
  }
  history.replaceState(null, '', '#' + tab.id.slice(4));
}
for (const t of tabs) t.addEventListener('click', () => show(t.id.slice(4)));
show(location.hash.slice(1) || '~A');
</script>
</body>
</html>"
  "The dashboard page: a tab per (name src label) and a frame per (name label), then the
tab shown first.")

(defun dashboard-shell-html (tabs initial)
  "The dashboard page for TABS, each (name src label), showing INITIAL first."
  (format nil +dashboard-shell-html+
          tabs
          (mapcar (lambda (tab) (list (first tab) (third tab))) tabs)
          initial))

(defclass gr8s-dashboard-acceptor (dashboard-command-acceptor)
  ((shell-path :initarg :shell-path :reader gr8s-dashboard-shell-path)
   (tabs :initarg :tabs :reader gr8s-dashboard-tabs)
   (hubble-backend :initarg :hubble-backend :initform nil :reader gr8s-dashboard-hubble-backend)
   (hubble-base :initarg :hubble-base :initform nil :reader gr8s-dashboard-hubble-base)
   ;; The cluster's DashboardTabs' apps, each on its own origin (dashboard-apps.lisp).
   (apps :initarg :apps :initform nil :reader gr8s-dashboard-apps))
  (:documentation "The loopback server of `gr8s dashboard': the tabbed page, Headlamp, and Hubble UI."))

(defmethod hunchentoot:acceptor-dispatch-request ((acceptor gr8s-dashboard-acceptor) request)
  (let ((path (hunchentoot:script-name request))
        (shell (gr8s-dashboard-shell-path acceptor))
        (hubble (gr8s-dashboard-hubble-base acceptor)))
    (cond
      ((or (string= path shell) (string= path (string-right-trim "/" shell)))
       (setf (hunchentoot:content-type*) "text/html; charset=utf-8"
             (hunchentoot:header-out :cache-control) "no-store"
             ;; The page's URL holds the session token; no frame may learn it.
             (hunchentoot:header-out :referrer-policy) "no-referrer")
       (let ((tabs (append (gr8s-dashboard-tabs acceptor)
                           (and (gr8s-dashboard-apps acceptor)
                                (dashboard-apps-tabs (gr8s-dashboard-apps acceptor))))))
         (dashboard-shell-html tabs (first (first tabs)))))
      ((and hubble (uiop:string-prefix-p hubble path))
       (hubble-ui-dispatch (gr8s-dashboard-hubble-backend acceptor) hubble request))
      (t (call-next-method)))))
