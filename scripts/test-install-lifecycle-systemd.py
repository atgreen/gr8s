#!/usr/bin/env python3
"""Destructive installation-lifecycle acceptance test for a disposable systemd VM."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
SERVICE = "gr8s-server.service"


def run(*arguments, environment=None, check=True):
    return subprocess.run(
        arguments,
        env=environment,
        text=True,
        capture_output=True,
        check=check,
    )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install(binary, ready_timeout="45"):
    environment = os.environ.copy()
    environment.update(
        {
            "INSTALL_GR8S_BINARY": str(binary),
            "INSTALL_GR8S_MODE": "server",
            "INSTALL_GR8S_EXEC_ARGS": (
                "serve --runtime containerd --state-directory /var/lib/gr8s/server "
                "--port 18191 --node-port 17448 "
                "--containerd-log-root /var/lib/gr8s/pods "
                "--kubeconfig /etc/gr8s/kubeconfig"
            ),
            "INSTALL_GR8S_READY_TIMEOUT": ready_timeout,
        }
    )
    return run("sh", str(REPOSITORY / "install.sh"), environment=environment, check=False)


def wrapper(path, binary, label):
    path.write_text(
        "#!/bin/sh\n" f"# lifecycle acceptance {label}\n" f'exec "{binary}" "$@"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unit_processes(service):
    result = run("systemctl", "show", "-p", "ControlGroup", "--value", service, check=False)
    control_group = result.stdout.strip()
    if not control_group.startswith("/"):
        return []
    processes = Path("/sys/fs/cgroup") / control_group.lstrip("/") / "cgroup.procs"
    return processes.read_text(encoding="utf-8").split() if processes.is_file() else []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--i-understand-this-is-a-disposable-vm", action="store_true")
    arguments = parser.parse_args()

    require(os.geteuid() == 0, "this acceptance test requires root")
    require(arguments.i_understand_this_is_a_disposable_vm, "disposable VM acknowledgement is required")
    require(Path("/run/systemd/system").is_dir(), "systemd is not the active service manager")
    require(arguments.binary.is_file() and os.access(arguments.binary, os.X_OK), "binary is not executable")

    evidence = {}
    marker = Path("/var/lib/gr8s/lifecycle-acceptance-marker")
    with tempfile.TemporaryDirectory(prefix="gr8s-lifecycle-acceptance.") as temporary:
        temporary = Path(temporary)
        version_one = temporary / "gr8s-v1"
        version_two = temporary / "gr8s-v2"
        broken = temporary / "gr8s-broken"
        wrapper(version_one, arguments.binary.resolve(), "v1")
        wrapper(version_two, arguments.binary.resolve(), "v2")
        broken.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
        broken.chmod(0o755)

        first = install(version_one)
        require(first.returncode == 0, first.stderr)
        require(run("systemctl", "is-active", "--quiet", SERVICE, check=False).returncode == 0, "service is not active")
        require(run("systemctl", "is-enabled", "--quiet", SERVICE, check=False).returncode == 0, "service is not enabled")
        evidence["install"] = {"active": True, "enabled": True, "sha256": digest(Path("/usr/local/bin/gr8s"))}

        upgraded = install(version_two)
        require(upgraded.returncode == 0, upgraded.stderr)
        require(digest(Path("/usr/local/bin/gr8s")) == digest(version_two), "upgrade binary was not published")
        require(digest(Path("/usr/local/bin/gr8s.previous")) == digest(version_one), "prior generation was not retained")
        evidence["upgrade"] = {"active": True, "sha256": digest(Path("/usr/local/bin/gr8s"))}

        failed = install(broken)
        require(failed.returncode != 0, "broken upgrade unexpectedly succeeded")
        require(digest(Path("/usr/local/bin/gr8s")) == digest(version_two), "failed upgrade did not roll back")
        require(run("systemctl", "is-active", "--quiet", SERVICE, check=False).returncode == 0, "rolled-back service is not active")
        evidence["rollback"] = {"installer_status": failed.returncode, "restored_sha256": digest(Path("/usr/local/bin/gr8s"))}

        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("preserve me\n", encoding="utf-8")
        run("/usr/local/bin/gr8s-killall.sh")
        require(run("systemctl", "is-active", "--quiet", SERVICE, check=False).returncode != 0, "killall left service active")
        require(not unit_processes(SERVICE), "killall left processes in the service cgroup")
        require(marker.is_file(), "killall removed persistent data")
        evidence["killall"] = {"inactive": True, "data_preserved": True}

        run("/usr/local/bin/gr8s-uninstall.sh")
        require(not Path("/usr/local/bin/gr8s").exists(), "uninstall retained binary")
        require(marker.is_file(), "uninstall removed persistent data")
        evidence["uninstall"] = {"binary_removed": True, "data_preserved": True}

        reinstalled = install(version_two)
        require(reinstalled.returncode == 0, reinstalled.stderr)
        run("/usr/local/bin/gr8s-uninstall.sh", "--purge")
        require(not Path("/var/lib/gr8s").exists(), "purge retained persistent data")
        require(run("systemctl", "is-active", "--quiet", SERVICE, check=False).returncode != 0, "purge left service active")
        require(not unit_processes(SERVICE), "purge left processes in the service cgroup")
        evidence["purge"] = {"data_removed": True, "inactive": True}

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
