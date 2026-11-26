#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Load the egress proxy's and the Gateway's sk_lookup programs in a real kernel.

Build the fixtures with:
  sbcl --script scripts/compile-endpoint-policy-fixture.lisp build/gr8s-egress-steering.json egress-steering
  sbcl --script scripts/compile-endpoint-policy-fixture.lisp build/gr8s-gateway-steering.json gateway-steering
Then, as root in a disposable VM:
  python3 scripts/test-egress-steering.py build/gr8s-egress-steering.json build/gr8s-gateway-steering.json

Attached in the agent's order (Gateway first), a connection to the egress proxy address
169.254.1.2 on any port -- a Gateway's port included -- reaches the proxy's one listener,
and a Gateway port on any other address still reaches the Gateway (podster-wv1w.2). So
does a connection to a synthetic address in 198.18.0.0/15, delivered by a local route,
and the accepted socket says which address it was (podster-wv1w.8).
"""
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    "service_lb", Path(__file__).with_name("test-service-lb-program.py"))
service_lb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service_lb)
endpoint = service_lb.endpoint

SK_LOOKUP, BPF_SK_LOOKUP = 30, 36


def attach(path):
    programs, maps = service_lb.fixture(path)
    kernel = endpoint.Kernel(programs, maps.ids, maps.descriptors,
                             program_types={name: (SK_LOOKUP, BPF_SK_LOOKUP) for name in programs})
    netns = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        link = kernel.bpf(28, struct.pack("<IIII", next(iter(kernel.program_fds.values())), netns, BPF_SK_LOOKUP, 0))
    finally:
        os.close(netns)
    return kernel, link


def main(egress_path, gateway_path):
    subprocess.run(["ip", "addr", "add", "169.254.1.2/32", "dev", "lo"], check=False, capture_output=True)
    subprocess.run(["ip", "route", "add", "local", "198.18.0.0/15", "dev", "lo"], check=False, capture_output=True)
    gateway, gateway_link = attach(gateway_path)
    egress, egress_link = attach(egress_path)
    try:
        with socket.socket() as proxy, socket.socket() as gateway_listener:
            proxy.bind(("169.254.1.2", 15443))
            proxy.listen()
            gateway_listener.bind(("127.0.0.1", 0))
            gateway_listener.listen()
            gateway_port = 8080
            egress.update("egress_listener_sock", struct.pack("<I", 0), struct.pack("<I", proxy.fileno()))
            gateway.update("gw_listener_sock", struct.pack("<I", gateway_port),
                           struct.pack("<I", gateway_listener.fileno()))
            for port in (443, 8443, gateway_port):
                with socket.socket() as client:
                    client.settimeout(2)
                    client.connect(("169.254.1.2", port))
                    accepted, _ = proxy.accept()
                    assert accepted.getsockname() == ("169.254.1.2", port), accepted.getsockname()
                    accepted.close()
            for address, port in (("198.18.0.7", 6379), ("198.19.255.254", 22), ("198.18.0.8", gateway_port)):
                with socket.socket() as client:
                    client.settimeout(2)
                    client.connect((address, port))
                    accepted, _ = proxy.accept()
                    assert accepted.getsockname() == (address, port), accepted.getsockname()
                    accepted.close()
            with socket.socket() as client:
                client.settimeout(2)
                client.connect(("127.0.0.1", gateway_port))
                accepted, _ = gateway_listener.accept()
                accepted.close()
        print("sk_lookup steering (Linux kernel): every port on the egress proxy address and the "
              "synthetic range reaches its listener, Gateway ports elsewhere reach the Gateway")
    finally:
        os.close(egress_link)
        os.close(gateway_link)
        egress.close()
        gateway.close()
        subprocess.run(["ip", "addr", "del", "169.254.1.2/32", "dev", "lo"], check=False, capture_output=True)
        subprocess.run(["ip", "route", "del", "local", "198.18.0.0/15", "dev", "lo"], check=False, capture_output=True)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
