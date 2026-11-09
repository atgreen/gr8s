#!/usr/bin/env python3
"""Rootless safety tests for gr8s killall and uninstall tools."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
KILLALL = REPOSITORY / "gr8s-killall.sh"
UNINSTALL = REPOSITORY / "gr8s-uninstall.sh"


class CleanupLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gr8s-cleanup-test.")
        temporary = Path(self.temporary.name)
        self.root = temporary / "root"
        self.tools = temporary / "tools"
        self.tools.mkdir()
        self.systemctl_log = temporary / "systemctl.log"
        self.umount_log = temporary / "umount.log"
        self.cgroup_root = temporary / "cgroup"
        self.cgroup_root.mkdir()

        self.systemctl = self.make_tool(
            "systemctl",
            'printf "%s\\n" "$*" >>"$GR8S_SYSTEMCTL_LOG"\n'
            '[ "${GR8S_SYSTEMCTL_FAIL:-}" != "$*" ] || exit 4\n'
            'if [ "${1:-}" = show ]; then\n'
            '  case "$*" in *LoadState*) printf "%s\\n" "${GR8S_LOAD_STATE:-loaded}" ;;\n'
            '    *ControlGroup*) printf "%s\\n" "${GR8S_CONTROL_GROUP:-}" ;; esac\n'
            'fi\n'
            'if [ "${1:-}" = kill ]; then touch "$GR8S_SYSTEMCTL_LOG.killed"; fi\n'
            'if [ "${1:-}" = is-active ]; then\n'
            '  [ ! -f "$GR8S_SYSTEMCTL_LOG.killed" ] || exit 3\n'
            '  exit "${GR8S_ACTIVE_STATUS:-3}"\n'
            'fi\n',
        )
        self.findmnt = self.make_tool(
            "findmnt",
            'printf "%s\\n" "$GR8S_TEST_MOUNTS"\n',
        )
        self.umount = self.make_tool(
            "umount",
            'printf "%s\\n" "$*" >>"$GR8S_UMOUNT_LOG"\n'
            '[ "${GR8S_UMOUNT_FAIL:-}" != "$*" ] || exit 5\n',
        )

    def tearDown(self):
        self.temporary.cleanup()

    def make_tool(self, name, body):
        path = self.tools / name
        path.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
        path.chmod(0o755)
        return path

    def environment(self):
        environment = os.environ.copy()
        environment.update(
            {
                "GR8S_ROOT": str(self.root),
                "GR8S_SYSTEMCTL": str(self.systemctl),
                "GR8S_SYSTEMCTL_LOG": str(self.systemctl_log),
                "GR8S_FINDMNT": str(self.findmnt),
                "GR8S_UMOUNT": str(self.umount),
                "GR8S_UMOUNT_LOG": str(self.umount_log),
                "GR8S_KILLALL_SCRIPT": str(KILLALL),
                "GR8S_CGROUP_ROOT": str(self.cgroup_root),
            }
        )
        return environment

    def run_script(self, script, *arguments, **environment_overrides):
        environment = self.environment()
        environment.update(environment_overrides)
        return subprocess.run(
            ["sh", str(script), *arguments],
            cwd=REPOSITORY,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def write(self, relative, content="owned\n"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_killall_is_idempotent_and_preserves_persistent_and_foreign_state(self):
        self.write("etc/systemd/system/gr8s-server.service")
        self.write("etc/systemd/system/gr8s-agent.service")
        runtime = self.write("run/gr8s/runtime.pid")
        persistent = self.write("var/lib/gr8s/server/objects/state.json")
        foreign = self.write("var/lib/foreign/keep")
        owned_mount = self.root / "var/lib/gr8s/z"
        nested_mount = self.root / "var/lib/gr8s/a/child"
        foreign_mount = self.root / "var/lib/foreign/mount"
        mounts = "\n".join((str(owned_mount), str(foreign_mount), str(nested_mount)))

        first = self.run_script(KILLALL, GR8S_TEST_MOUNTS=mounts)
        second = self.run_script(KILLALL, GR8S_TEST_MOUNTS="")
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(0, second.returncode, second.stderr)
        self.assertFalse(runtime.exists())
        self.assertTrue(persistent.is_file())
        self.assertTrue(foreign.is_file())

        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        for service in ("gr8s-server.service", "gr8s-agent.service"):
            self.assertGreaterEqual(calls.count(f"stop {service}"), 2)
            self.assertGreaterEqual(
                calls.count(f"kill --signal=KILL --kill-who=all {service}"), 2
            )
        self.assertEqual(
            [f"-l -- {nested_mount}", f"-l -- {owned_mount}"],
            self.umount_log.read_text(encoding="utf-8").splitlines(),
        )
        self.assertNotIn(str(foreign_mount), self.umount_log.read_text(encoding="utf-8"))

    def test_killall_attempts_every_cleanup_but_reports_real_failures(self):
        self.write("etc/systemd/system/gr8s-server.service")
        self.write("etc/systemd/system/gr8s-agent.service")
        mount = self.root / "var/lib/gr8s/server/agent/containerd/run"
        result = self.run_script(
            KILLALL,
            GR8S_TEST_MOUNTS=str(mount),
            GR8S_SYSTEMCTL_FAIL="stop gr8s-server.service",
            GR8S_ACTIVE_STATUS="0",
            GR8S_UMOUNT_FAIL=f"-l -- {mount}",
        )
        self.assertNotEqual(0, result.returncode)
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("kill --signal=KILL --kill-who=all gr8s-server.service", calls)
        self.assertIn("stop gr8s-agent.service", calls)
        self.assertIn(f"-l -- {mount}", self.umount_log.read_text(encoding="utf-8"))

    def test_killall_stops_loaded_units_even_when_unit_files_are_missing(self):
        result = self.run_script(KILLALL, GR8S_TEST_MOUNTS="")
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("stop gr8s-server.service", calls)
        self.assertIn("kill --signal=KILL --kill-who=all gr8s-agent.service", calls)

    def test_killall_reports_a_unit_that_remains_active_after_sigkill(self):
        processes = self.cgroup_root / "system.slice/gr8s-server.service/cgroup.procs"
        processes.parent.mkdir(parents=True)
        processes.write_text("123\n", encoding="utf-8")
        result = self.run_script(
            KILLALL,
            GR8S_TEST_MOUNTS="",
            GR8S_CONTROL_GROUP="/system.slice/gr8s-server.service",
            GR8S_SYSTEMCTL_FAIL="kill --signal=KILL --kill-who=all gr8s-server.service",
        )
        self.assertNotEqual(0, result.returncode)

    def test_killall_termination_aborts_and_removes_temporary_files(self):
        temporary_files = Path(self.temporary.name) / "temporary-files"
        temporary_files.mkdir()
        terminating_findmnt = self.make_tool(
            "terminating-findmnt", 'kill -TERM "$PPID"\nprintf "/foreign\\n"\n'
        )
        runtime = self.write("run/gr8s/runtime.pid")
        result = self.run_script(
            KILLALL,
            GR8S_FINDMNT=str(terminating_findmnt),
            TMPDIR=str(temporary_files),
        )
        self.assertEqual(143, result.returncode, result.stderr)
        self.assertEqual([], list(temporary_files.iterdir()))
        self.assertTrue(runtime.is_file())

    def test_killall_treats_not_found_units_as_idempotent(self):
        result = self.run_script(
            KILLALL,
            GR8S_TEST_MOUNTS="",
            GR8S_LOAD_STATE="not-found",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertFalse(any(call.startswith("stop ") for call in calls))
        self.assertFalse(any(call.startswith("kill ") for call in calls))

    def seed_installation(self):
        for path in (
            "usr/local/bin/gr8s",
            "usr/local/bin/gr8s.previous",
            "usr/local/bin/gr8s-killall.sh",
            "usr/local/bin/gr8s-uninstall.sh",
            "etc/gr8s/server.env",
            "etc/gr8s/kubeconfig",
            "etc/systemd/system/gr8s-server.service",
        ):
            self.write(path)
        return self.write("var/lib/gr8s/server/objects/state.json", "persistent\n")

    def test_uninstall_preserves_cluster_data_by_default(self):
        persistent = self.seed_installation()
        foreign = self.write("opt/foreign/keep")
        result = self.run_script(UNINSTALL, GR8S_TEST_MOUNTS="")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(persistent.is_file())
        self.assertTrue(foreign.is_file())
        self.assertFalse((self.root / "usr/local/bin/gr8s").exists())
        self.assertFalse((self.root / "etc/gr8s").exists())
        self.assertFalse((self.root / "etc/systemd/system/gr8s-server.service").exists())

    def test_uninstall_purge_requires_explicit_flag(self):
        persistent = self.seed_installation()
        result = self.run_script(UNINSTALL, "--purge", GR8S_TEST_MOUNTS="")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(persistent.exists())
        self.assertFalse((self.root / "var/lib/gr8s").exists())

    def test_uninstall_rejects_unknown_arguments_without_mutation(self):
        persistent = self.seed_installation()
        result = self.run_script(UNINSTALL, "--force", GR8S_TEST_MOUNTS="")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("--purge", result.stderr)
        self.assertTrue(persistent.is_file())
        self.assertTrue((self.root / "usr/local/bin/gr8s").is_file())

    def test_uninstall_recovers_when_killall_helper_is_missing(self):
        persistent = self.seed_installation()
        (self.root / "usr/local/bin/gr8s-killall.sh").unlink()
        missing = self.root / "usr/local/bin/gr8s-killall.sh"
        result = self.run_script(
            UNINSTALL,
            GR8S_KILLALL_SCRIPT=str(missing),
            GR8S_TEST_MOUNTS="",
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(persistent.is_file())
        self.assertFalse((self.root / "usr/local/bin/gr8s").exists())
        calls = self.systemctl_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("stop gr8s-server.service", calls)
        self.assertIn("kill --signal=KILL --kill-who=all gr8s-agent.service", calls)

    def test_uninstall_fallback_termination_preserves_install_and_cleans_temps(self):
        persistent = self.seed_installation()
        missing = self.root / "usr/local/bin/missing-killall"
        temporary_files = Path(self.temporary.name) / "fallback-temporary-files"
        temporary_files.mkdir()
        terminating_findmnt = self.make_tool(
            "fallback-terminating-findmnt", 'kill -TERM "$PPID"\nprintf "/foreign\\n"\n'
        )
        result = self.run_script(
            UNINSTALL,
            GR8S_KILLALL_SCRIPT=str(missing),
            GR8S_FINDMNT=str(terminating_findmnt),
            TMPDIR=str(temporary_files),
        )
        self.assertEqual(143, result.returncode, result.stderr)
        self.assertEqual([], list(temporary_files.iterdir()))
        self.assertTrue(persistent.is_file())
        self.assertTrue((self.root / "usr/local/bin/gr8s").is_file())

    def test_uninstall_does_not_remove_artifacts_after_genuine_killall_failure(self):
        persistent = self.seed_installation()
        failing = self.make_tool("failing-killall", "exit 9\n")
        result = self.run_script(
            UNINSTALL,
            GR8S_KILLALL_SCRIPT=str(failing),
            GR8S_TEST_MOUNTS="",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertTrue(persistent.is_file())
        self.assertTrue((self.root / "usr/local/bin/gr8s").is_file())

    def test_uninstall_removes_stale_enablement_when_unit_file_is_missing(self):
        persistent = self.seed_installation()
        (self.root / "etc/systemd/system/gr8s-server.service").unlink()
        link = self.write("etc/systemd/system/multi-user.target.wants/gr8s-server.service")
        result = self.run_script(UNINSTALL, GR8S_TEST_MOUNTS="")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(persistent.is_file())
        self.assertFalse(link.exists())
        self.assertIn(
            "disable gr8s-server.service",
            self.systemctl_log.read_text(encoding="utf-8").splitlines(),
        )

    def test_disable_failure_reports_error_but_retry_converges(self):
        self.seed_installation()
        link = self.write("etc/systemd/system/multi-user.target.wants/gr8s-server.service")
        failed = self.run_script(
            UNINSTALL,
            GR8S_TEST_MOUNTS="",
            GR8S_SYSTEMCTL_FAIL="disable gr8s-server.service",
        )
        self.assertNotEqual(0, failed.returncode)
        self.assertFalse(link.exists())
        retried = self.run_script(UNINSTALL, GR8S_TEST_MOUNTS="", GR8S_LOAD_STATE="not-found")
        self.assertEqual(0, retried.returncode, retried.stderr)


if __name__ == "__main__":
    unittest.main()
