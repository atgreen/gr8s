#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Evaluate Lisp forms in a running gr8s started with --debug-slynk-port.

Speaks just enough of the Slynk protocol for scripted use: each message is six hex
digits giving its UTF-8 byte length, then an s-expression. The first message must
be the bare session secret from <state>/debug/slynk.secret. Each FORM is evaluated by
gr8s::debug-eval in the GR8S package, for example:

    gr8s-debug.py --port 4005 --state-directory DIR '(debug-threads)'
    gr8s-debug.py --port 4005 --state-directory DIR '(debug-pod "default" "web")'
"""

import argparse
import socket
import sys
from pathlib import Path


def send(connection, text):
    """Write one length-prefixed protocol message."""
    payload = text.encode()
    connection.sendall(f"{len(payload):06x}".encode() + payload)


def receive(connection):
    """Read one length-prefixed protocol message."""
    def exactly(count):
        data = b""
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise EOFError("connection closed; check the port and secret")
            data += chunk
        return data
    return exactly(int(exactly(6), 16)).decode()


def lisp_string(text):
    """Quote TEXT as a Lisp string literal."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_reply(message, request_id):
    """Return (status, payload) when MESSAGE is the reply to REQUEST_ID, otherwise None."""
    if not message.startswith("(:return "):
        return None
    if not message.rstrip().endswith(f" {request_id})"):
        return None
    start = message.find("(:", len("(:return "))
    status = message[start + 2:].split(" ", 1)[0].rstrip(")")
    quote = message.find('"', start)
    if quote < 0:
        return status, ""
    chars, index = [], quote + 1
    while message[index] != '"':
        if message[index] == "\\":
            index += 1
        chars.append(message[index])
        index += 1
    return status, "".join(chars)


def evaluate(connection, form, request_id):
    """Evaluate FORM remotely and return (status, output), ignoring unrelated events."""
    wrapped = f"(gr8s::debug-eval {lisp_string(form)})"
    send(connection, f"(:emacs-rex {wrapped} \"GR8S\" t {request_id})")
    while True:
        reply = parse_reply(receive(connection), request_id)
        if reply:
            return reply


def main():
    """Authenticate once, then evaluate each form in order."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("forms", nargs="+")
    arguments = parser.parse_args()
    secret = (arguments.state_directory / "debug" / "slynk.secret").read_text().strip()
    with socket.create_connection(("127.0.0.1", arguments.port), timeout=arguments.timeout) as connection:
        send(connection, secret)
        failed = False
        for request_id, form in enumerate(arguments.forms, start=1):
            status, output = evaluate(connection, form, request_id)
            sys.stdout.write(output)
            if status != "ok" or output.startswith("ERROR: "):
                failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
