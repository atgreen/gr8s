#!/usr/bin/env python3
"""Rootless contract tests for the systemd installation lifecycle."""

import os
import hashlib
import stat
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
INSTALLER = REPOSITORY / "install.sh"


class InstallLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gr8s-install-test.")
        self.root = Path(self.temporary.name) / "root"
        self.tools = Path(self.temporary.name) / "tools"
        self.tools.mkdir()
        self.systemctl_log = Path(self.temporary.name) / "systemctl.log"
        self.binary = Path(self.temporary.name) / "gr8s"
        self.binary.write_text("#!/bin/sh\necho test-gr8s\n", encoding="utf-8")
        self.binary.chmod(0o755)
        self.systemctl = self.tools / "systemctl"
        self.systemctl.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >>\"$INSTALL_GR8S_SYSTEMCTL_LOG\"\n"
            "if [ \"${INSTALL_GR8S_SYSTEMCTL_FAIL:-}\" = \"$*\" ]; then exit 4; fi\n"
            "if [ \"${1:-}\" = restart ] && "
            "[ \"${INSTALL_GR8S_SYSTEMCTL_FAIL_RESTART:-}\" = yes ]; then exit 4; fi\n"
            "if [ \"${1:-}\" = is-active ] && "
            "[ \"${INSTALL_GR8S_SYSTEMCTL_TRANSIENT:-}\" = yes ]; then\n"
            "  count_file=$INSTALL_GR8S_SYSTEMCTL_LOG.transient\n"
            "  count=0; [ ! -f \"$count_file\" ] || count=$(cat \"$count_file\")\n"
            "  count=$((count + 1)); printf '%s\\n' \"$count\" >\"$count_file\"\n"
            "  [ \"$count\" -eq 1 ] && exit 0\n"
            "  exit 3\n"
            "fi\n"
            "if [ \"${1:-}\" = is-active ] && "
            "[ \"${INSTALL_GR8S_SYSTEMCTL_ACTIVE:-active}\" != active ]; then exit 3; fi\n",
            encoding="utf-8",
        )
        self.systemctl.chmod(0o755)
        self.failing_copy = self.tools / "failing-copy"
        self.failing_copy.write_text("#!/bin/sh\nexit 5\n", encoding="utf-8")
        self.failing_copy.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def install(self, mode, arguments):
        environment = os.environ.copy()
        environment.update(
            {
                "INSTALL_GR8S_BINARY": str(self.binary),
                "INSTALL_GR8S_EXEC_ARGS": arguments,
                "INSTALL_GR8S_MODE": mode,
                "INSTALL_GR8S_ROOT": str(self.root),
                "INSTALL_GR8S_SYSTEMCTL": str(self.systemctl),
                "INSTALL_GR8S_SYSTEMCTL_LOG": str(self.systemctl_log),
                "INSTALL_GR8S_STABILITY_WINDOW": "0",
                "INSTALL_GR8S_SYSTEMCTL_TIMEOUT": "2",
            }
        )
        return subprocess.run(
            ["sh", str(INSTALLER)],
            cwd=REPOSITORY,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def environment(self, mode, arguments, **overrides):
        environment = os.environ.copy()
        environment.update(
            {
                "INSTALL_GR8S_BINARY": str(self.binary),
                "INSTALL_GR8S_EXEC_ARGS": arguments,
                "INSTALL_GR8S_MODE": mode,
                "INSTALL_GR8S_ROOT": str(self.root),
                "INSTALL_GR8S_SYSTEMCTL": str(self.systemctl),
                "INSTALL_GR8S_SYSTEMCTL_LOG": str(self.systemctl_log),
                "INSTALL_GR8S_STABILITY_WINDOW": "0",
                "INSTALL_GR8S_SYSTEMCTL_TIMEOUT": "2",
            }
        )
        environment.update(overrides)
        return environment

    def run_installer(self, mode, arguments, **overrides):
        return subprocess.run(
            ["sh", str(INSTALLER)],
            cwd=REPOSITORY,
            env=self.environment(mode, arguments, **overrides),
            text=True,
            capture_output=True,
            check=False,
        )

    def run_download_installer(self, **overrides):
        environment = self.environment(
            "server", "serve --state-directory /var/lib/gr8s/server", **overrides
        )
        environment.pop("INSTALL_GR8S_BINARY", None)
        return subprocess.run(
            ["sh", str(INSTALLER)],
            cwd=REPOSITORY,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def serve_binary(self):
        binary = self.binary.read_bytes()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                if handler.path == "/redirect":
                    handler.send_response(302)
                    handler.send_header("Location", "/gr8s")
                    handler.end_headers()
                elif handler.path == "/gr8s":
                    handler.send_response(200)
                    handler.send_header("Content-Length", str(len(binary)))
                    handler.end_headers()
                    handler.wfile.write(binary)
                else:
                    handler.send_error(404)

            def log_message(handler, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def assert_mode(self, relative_path, expected):
        actual = stat.S_IMODE((self.root / relative_path).stat().st_mode)
        self.assertEqual(expected, actual, relative_path)

    def test_server_install_writes_persistent_configuration_and_unit(self):
        result = self.install(
            "server",
            "serve --state-directory /var/lib/gr8s/server --kubeconfig /etc/gr8s/kubeconfig",
        )
        self.assertEqual(0, result.returncode, result.stderr)

        installed = self.root / "usr/local/bin/gr8s"
        self.assertEqual(self.binary.read_bytes(), installed.read_bytes())
        self.assert_mode("usr/local/bin/gr8s", 0o755)
        self.assertEqual(
            (REPOSITORY / "gr8s-killall.sh").read_bytes(),
            (self.root / "usr/local/bin/gr8s-killall.sh").read_bytes(),
        )
        self.assertEqual(
            (REPOSITORY / "gr8s-uninstall.sh").read_bytes(),
            (self.root / "usr/local/bin/gr8s-uninstall.sh").read_bytes(),
        )
        self.assert_mode("usr/local/bin/gr8s-killall.sh", 0o755)
        self.assert_mode("usr/local/bin/gr8s-uninstall.sh", 0o755)

        environment = self.root / "etc/gr8s/server.env"
        self.assertEqual(
            "GR8S_EXEC_ARGS=serve --state-directory /var/lib/gr8s/server "
            "--kubeconfig /etc/gr8s/kubeconfig\n",
            environment.read_text(encoding="utf-8"),
        )
        self.assert_mode("etc/gr8s/server.env", 0o600)

        unit = (self.root / "etc/systemd/system/gr8s-server.service").read_text(encoding="utf-8")
        self.assertIn("EnvironmentFile=/etc/gr8s/server.env", unit)
        self.assertIn("ExecStart=/usr/local/bin/gr8s $GR8S_EXEC_ARGS", unit)
        self.assertIn("Restart=always", unit)
        self.assertNotIn(str(self.root), unit)
        self.assert_mode("etc/systemd/system/gr8s-server.service", 0o644)

        installed_files = {
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            {
                "etc/gr8s/server.env",
                "etc/systemd/system/gr8s-server.service",
                "usr/local/bin/gr8s",
                "usr/local/bin/gr8s-killall.sh",
                "usr/local/bin/gr8s-uninstall.sh",
            },
            installed_files,
        )

        self.assertEqual(
            [
                "daemon-reload",
                "enable gr8s-server.service",
                "restart gr8s-server.service",
                "is-active --quiet gr8s-server.service",
            ],
            self.systemctl_log.read_text(encoding="utf-8").splitlines(),
        )

    def test_agent_install_is_idempotent_and_selects_only_agent_service(self):
        arguments = (
            "agent --server 192.0.2.10:18090 --node-name worker-1 "
            "--state-directory /var/lib/gr8s/agent"
        )
        first = self.install("agent", arguments)
        second = self.install("agent", arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)

        self.assertTrue((self.root / "etc/gr8s/agent.env").is_file())
        self.assertTrue((self.root / "etc/systemd/system/gr8s-agent.service").is_file())
        self.assertFalse((self.root / "etc/systemd/system/gr8s-server.service").exists())
        self.assertEqual(
            2,
            self.systemctl_log.read_text(encoding="utf-8").splitlines().count(
                "restart gr8s-agent.service"
            ),
        )

    def test_changing_roles_retires_the_previous_service(self):
        server = self.install("server", "serve --state-directory /var/lib/gr8s/server")
        agent = self.install(
            "agent",
            "agent --server 192.0.2.10:18090 --node-name worker-1 "
            "--state-directory /var/lib/gr8s/agent",
        )
        self.assertEqual(0, server.returncode, server.stderr)
        self.assertEqual(0, agent.returncode, agent.stderr)
        self.assertFalse((self.root / "etc/gr8s/server.env").exists())
        self.assertFalse((self.root / "etc/systemd/system/gr8s-server.service").exists())
        self.assertTrue((self.root / "etc/systemd/system/gr8s-agent.service").is_file())
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("stop gr8s-server.service", calls)
        self.assertIn("disable gr8s-server.service", calls)

    def test_rejects_arguments_environment_file_cannot_round_trip(self):
        for unsafe in (
            "serve --node-name 'two words'",
            'serve --node-name "two words"',
            "serve --node-name two\\ words",
            "serve\nGR8S_INJECTED=yes",
        ):
            with self.subTest(arguments=unsafe):
                result = self.install("server", unsafe)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("INSTALL_GR8S_EXEC_ARGS", result.stderr)
                self.assertFalse(self.root.exists())

    def test_rejects_unknown_mode_before_writing(self):
        result = self.install("controller", "serve")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("INSTALL_GR8S_MODE", result.stderr)
        self.assertFalse(self.root.exists())

    def test_upgrade_keeps_exactly_one_previous_binary(self):
        arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        old = (self.root / "usr/local/bin/gr8s").read_bytes()

        self.binary.write_text("#!/bin/sh\necho upgraded-gr8s\n", encoding="utf-8")
        self.binary.chmod(0o755)
        second = self.install("server", arguments)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertEqual(old, (self.root / "usr/local/bin/gr8s.previous").read_bytes())
        self.assertEqual(self.binary.read_bytes(), (self.root / "usr/local/bin/gr8s").read_bytes())
        self.assertFalse((self.root / "usr/local/bin/gr8s.previous.previous").exists())
        self.assertIn(
            "is-active --quiet gr8s-server.service",
            self.systemctl_log.read_text(encoding="utf-8").splitlines(),
        )

    def test_checksum_failure_does_not_mutate_an_existing_install(self):
        arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        before = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        calls_before = self.systemctl_log.read_bytes()

        self.binary.write_text("#!/bin/sh\necho tampered\n", encoding="utf-8")
        result = self.run_installer(
            "server",
            "serve --state-directory /var/lib/gr8s/different",
            INSTALL_GR8S_SHA256="0" * 64,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SHA-256", result.stderr)
        after = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(calls_before, self.systemctl_log.read_bytes())

    def test_downloads_explicit_checksum_pinned_url(self):
        base_url = self.serve_binary()
        checksum = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.run_download_installer(
            INSTALL_GR8S_URL=f"{base_url}/gr8s", INSTALL_GR8S_SHA256=checksum
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            self.binary.read_bytes(), (self.root / "usr/local/bin/gr8s").read_bytes()
        )

    def test_download_follows_redirects(self):
        base_url = self.serve_binary()
        checksum = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.run_download_installer(
            INSTALL_GR8S_URL=f"{base_url}/redirect", INSTALL_GR8S_SHA256=checksum
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_download_requires_checksum_before_network_or_writes(self):
        result = self.run_download_installer(INSTALL_GR8S_URL="http://127.0.0.1:1/gr8s")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("INSTALL_GR8S_SHA256", result.stderr)
        self.assertFalse(self.root.exists())

    def test_download_http_failure_does_not_write_installation(self):
        base_url = self.serve_binary()
        result = self.run_download_installer(
            INSTALL_GR8S_URL=f"{base_url}/missing", INSTALL_GR8S_SHA256="0" * 64
        )
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.root.exists())

    def test_download_checksum_failure_does_not_mutate_existing_install(self):
        initial = self.install("server", "serve --state-directory /var/lib/gr8s/server")
        self.assertEqual(0, initial.returncode, initial.stderr)
        before = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        calls_before = self.systemctl_log.read_bytes()
        base_url = self.serve_binary()
        result = self.run_download_installer(
            INSTALL_GR8S_URL=f"{base_url}/gr8s", INSTALL_GR8S_SHA256="0" * 64
        )
        self.assertNotEqual(0, result.returncode)
        after = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(calls_before, self.systemctl_log.read_bytes())

    def test_download_temporary_file_is_removed_after_checksum_failure(self):
        download_directory = Path(self.temporary.name) / "downloads"
        download_directory.mkdir()
        base_url = self.serve_binary()
        result = self.run_download_installer(
            INSTALL_GR8S_URL=f"{base_url}/gr8s",
            INSTALL_GR8S_SHA256="0" * 64,
            TMPDIR=str(download_directory),
        )
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list(download_directory.iterdir()))

    def test_download_termination_aborts_and_removes_temporary_file(self):
        download_directory = Path(self.temporary.name) / "downloads"
        download_directory.mkdir()
        terminating_curl = self.tools / "terminating-curl"
        terminating_curl.write_text(
            "#!/bin/sh\n"
            "output=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
            "done\n"
            "cp -f \"$INSTALL_GR8S_CURL_FIXTURE\" \"$output\"\n"
            "kill -TERM \"$PPID\"\n",
            encoding="utf-8",
        )
        terminating_curl.chmod(0o755)
        result = self.run_download_installer(
            INSTALL_GR8S_URL="https://downloads.example/gr8s",
            INSTALL_GR8S_SHA256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            INSTALL_GR8S_CURL=str(terminating_curl),
            INSTALL_GR8S_CURL_FIXTURE=str(self.binary),
            TMPDIR=str(download_directory),
        )
        self.assertEqual(143, result.returncode, result.stderr)
        self.assertEqual([], list(download_directory.iterdir()))
        self.assertFalse(self.root.exists())

    def test_version_download_rejects_unsupported_architecture_before_writes(self):
        result = self.run_download_installer(
            INSTALL_GR8S_VERSION="v1.2.3",
            INSTALL_GR8S_SHA256="0" * 64,
            INSTALL_GR8S_ARCH="sparc64",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("unsupported release architecture", result.stderr)
        self.assertFalse(self.root.exists())

    def test_version_release_url_maps_supported_architecture(self):
        curl_log = Path(self.temporary.name) / "curl.log"
        fake_curl = self.tools / "curl"
        fake_curl.write_text(
            "#!/bin/sh\n"
            "output=\nurl=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --output) output=$2; shift 2 ;;\n"
            "    http*) url=$1; shift ;;\n"
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            "printf '%s\\n' \"$url\" >\"$INSTALL_GR8S_CURL_LOG\"\n"
            "cp -f \"$INSTALL_GR8S_CURL_FIXTURE\" \"$output\"\n",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)
        checksum = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.run_download_installer(
            INSTALL_GR8S_VERSION="v1.2.3",
            INSTALL_GR8S_SHA256=checksum,
            INSTALL_GR8S_CURL=str(fake_curl),
            INSTALL_GR8S_CURL_LOG=str(curl_log),
            INSTALL_GR8S_CURL_FIXTURE=str(self.binary),
            INSTALL_GR8S_ARCH="x86_64",
            INSTALL_GR8S_RELEASE_BASE="https://downloads.example/releases",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "https://downloads.example/releases/v1.2.3/gr8s-linux-amd64\n",
            curl_log.read_text(encoding="utf-8"),
        )

    def test_staging_failure_restores_a_clean_host_tree(self):
        result = self.run_installer(
            "server",
            "serve --state-directory /var/lib/gr8s/server",
            INSTALL_GR8S_STAGE_COPY=str(self.failing_copy),
        )
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.systemctl_log.exists())

    def test_refuses_preexisting_lifecycle_artifact_without_main_install(self):
        existing = self.root / "usr/local/bin/gr8s-killall.sh"
        existing.parent.mkdir(parents=True)
        existing.write_text("foreign or incomplete\n", encoding="utf-8")
        result = self.install("server", "serve --state-directory /var/lib/gr8s/server")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("incomplete", result.stderr)
        self.assertEqual("foreign or incomplete\n", existing.read_text(encoding="utf-8"))
        self.assertFalse((self.root / "usr/local/bin/gr8s").exists())

    def test_refuses_orphan_configuration_or_unit_without_main_install(self):
        for relative in (
            "etc/gr8s/server.env",
            "etc/systemd/system/gr8s-server.service",
        ):
            with self.subTest(relative=relative):
                orphan = self.root / relative
                orphan.parent.mkdir(parents=True, exist_ok=True)
                orphan.write_text("orphan\n", encoding="utf-8")
                result = self.install("server", "serve --state-directory /var/lib/gr8s/server")
                self.assertNotEqual(0, result.returncode)
                self.assertIn("incomplete", result.stderr)
                self.assertEqual("orphan\n", orphan.read_text(encoding="utf-8"))
                if orphan.exists():
                    orphan.unlink()

    def test_partial_directory_creation_failure_cleans_new_directories(self):
        self.root.mkdir(parents=True)
        blocking_path = self.root / "etc"
        blocking_path.write_text("not a directory\n", encoding="utf-8")
        result = self.install("server", "serve --state-directory /var/lib/gr8s/server")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / "usr").exists())
        self.assertEqual("not a directory\n", blocking_path.read_text(encoding="utf-8"))

    def test_fresh_install_requires_service_readiness(self):
        result = self.run_installer(
            "server",
            "serve --state-directory /var/lib/gr8s/server",
            INSTALL_GR8S_READY_TIMEOUT="0",
            INSTALL_GR8S_SYSTEMCTL_ACTIVE="failed",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("is-active --quiet gr8s-server.service", self.systemctl_log.read_text())
        self.assertFalse(self.root.exists())

    def test_transient_active_state_does_not_satisfy_stability_window(self):
        result = self.run_installer(
            "server",
            "serve --state-directory /var/lib/gr8s/server",
            INSTALL_GR8S_READY_TIMEOUT="2",
            INSTALL_GR8S_STABILITY_WINDOW="1",
            INSTALL_GR8S_SYSTEMCTL_TRANSIENT="yes",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.root.exists())

    def test_failed_upgrade_readiness_restores_binary_config_and_unit(self):
        original_arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", original_arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        paths = (
            "usr/local/bin/gr8s",
            "etc/gr8s/server.env",
            "etc/systemd/system/gr8s-server.service",
        )
        before = {path: (self.root / path).read_bytes() for path in paths}

        self.binary.write_text("#!/bin/sh\necho broken-upgrade\n", encoding="utf-8")
        self.binary.chmod(0o755)
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        result = self.run_installer(
            "server",
            "serve --state-directory /var/lib/gr8s/new-state",
            INSTALL_GR8S_SHA256=digest,
            INSTALL_GR8S_READY_TIMEOUT="0",
            INSTALL_GR8S_SYSTEMCTL_ACTIVE="failed",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("rolling back", result.stderr)
        self.assertEqual(before, {path: (self.root / path).read_bytes() for path in paths})
        self.assertFalse((self.root / "usr/local/bin/gr8s.previous").exists())
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(3, calls.count("restart gr8s-server.service"))

    def test_every_post_publish_systemd_failure_rolls_back(self):
        arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        paths = (
            "usr/local/bin/gr8s",
            "etc/gr8s/server.env",
            "etc/systemd/system/gr8s-server.service",
        )
        expected = {path: (self.root / path).read_bytes() for path in paths}

        for index, failed_call in enumerate(
            ("daemon-reload", "enable gr8s-server.service", "restart gr8s-server.service"),
            start=1,
        ):
            with self.subTest(failed_call=failed_call):
                self.binary.write_text(
                    f"#!/bin/sh\necho failed-upgrade-{index}\n", encoding="utf-8"
                )
                self.binary.chmod(0o755)
                result = self.run_installer(
                    "server",
                    f"serve --state-directory /var/lib/gr8s/failed-{index}",
                    INSTALL_GR8S_SYSTEMCTL_FAIL=failed_call,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(
                    expected,
                    {path: (self.root / path).read_bytes() for path in paths},
                )

    def test_rollback_reports_failure_to_restore_running_service(self):
        arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        old_binary = (self.root / "usr/local/bin/gr8s").read_bytes()
        self.binary.write_text("#!/bin/sh\necho upgraded\n", encoding="utf-8")
        self.binary.chmod(0o755)
        result = self.run_installer(
            "server",
            arguments,
            INSTALL_GR8S_SYSTEMCTL_FAIL="daemon-reload",
            INSTALL_GR8S_SYSTEMCTL_FAIL_RESTART="yes",
            INSTALL_GR8S_SYSTEMCTL_TIMEOUT="1",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("rollback incomplete", result.stderr)
        self.assertEqual(old_binary, (self.root / "usr/local/bin/gr8s").read_bytes())

    def test_failed_role_transition_disables_new_role_and_restores_old_role(self):
        server_arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", server_arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        original_binary = (self.root / "usr/local/bin/gr8s").read_bytes()

        self.binary.write_text("#!/bin/sh\necho broken-agent\n", encoding="utf-8")
        self.binary.chmod(0o755)
        result = self.run_installer(
            "agent",
            "agent --server 192.0.2.10:18090 --node-name worker-1 "
            "--state-directory /var/lib/gr8s/agent",
            INSTALL_GR8S_READY_TIMEOUT="0",
            INSTALL_GR8S_SYSTEMCTL_ACTIVE="failed",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(original_binary, (self.root / "usr/local/bin/gr8s").read_bytes())
        self.assertTrue((self.root / "etc/gr8s/server.env").is_file())
        self.assertTrue((self.root / "etc/systemd/system/gr8s-server.service").is_file())
        self.assertFalse((self.root / "etc/gr8s/agent.env").exists())
        self.assertFalse((self.root / "etc/systemd/system/gr8s-agent.service").exists())
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("stop gr8s-agent.service", calls)
        self.assertIn("disable gr8s-agent.service", calls)
        self.assertIn("enable gr8s-server.service", calls)
        self.assertIn("restart gr8s-server.service", calls)
        self.assertEqual("is-active --quiet gr8s-server.service", calls[-1])

    def test_failed_later_upgrade_preserves_the_retained_older_generation(self):
        arguments = "serve --state-directory /var/lib/gr8s/server"
        first = self.install("server", arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        generation_a = (self.root / "usr/local/bin/gr8s").read_bytes()

        self.binary.write_text("#!/bin/sh\necho generation-b\n", encoding="utf-8")
        self.binary.chmod(0o755)
        second = self.install("server", arguments)
        self.assertEqual(0, second.returncode, second.stderr)
        generation_b = (self.root / "usr/local/bin/gr8s").read_bytes()
        self.assertEqual(generation_a, (self.root / "usr/local/bin/gr8s.previous").read_bytes())

        self.binary.write_text("#!/bin/sh\necho generation-c-broken\n", encoding="utf-8")
        self.binary.chmod(0o755)
        failed = self.run_installer(
            "server",
            arguments,
            INSTALL_GR8S_READY_TIMEOUT="0",
            INSTALL_GR8S_SYSTEMCTL_ACTIVE="failed",
        )
        self.assertNotEqual(0, failed.returncode)
        self.assertEqual(generation_b, (self.root / "usr/local/bin/gr8s").read_bytes())
        self.assertEqual(generation_a, (self.root / "usr/local/bin/gr8s.previous").read_bytes())


if __name__ == "__main__":
    unittest.main()
