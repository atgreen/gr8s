#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Check packet bounds across a map lookup in a disposable root VM.

This tests compiler pointer provenance, not Service or CNI integration.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--disposable-vm", action="store_true")
    args = parser.parse_args()
    if not args.disposable_vm or os.geteuid() != 0:
        parser.error("run --disposable-vm as root inside a disposable VM")
    spec = importlib.util.spec_from_file_location("packet", Path(__file__).with_name("test-service-packet-program.py"))
    packet = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packet)
    programs, ids, descriptors = packet.read_fixture(args.fixture, names=("gr8s_pointer_probe",))
    runner = packet.Kernel(programs, ids, descriptors)
    try:
        for key in range(3):
            runner.update("pointer_state", struct.pack("<I", key), struct.pack("<Q", 7))
        for protocol in (6, 17):
            for size in (0, 1, 32, 1400):
                data = packet.packet(protocol=protocol, payload=b"x" * size)
                verdict, output = runner.run("gr8s_pointer_probe", data)
                assert verdict == data[26] + 21 and output == data, (protocol, size, verdict)
        print(json.dumps({"passed": True, "kernel": True, "cases": 8}))
    finally:
        runner.close()


if __name__ == "__main__":
    main()
