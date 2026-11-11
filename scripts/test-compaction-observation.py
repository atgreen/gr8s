#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Verify busy observations cannot certify progress or hide fresh failures."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("compaction_probe", Path(__file__).with_name("test-compaction-cluster-native.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

fresh = dict(busy=False, blocked=False, term=1, applied=17, mutualTls=True,
             heapLimitMiB=384, churnError=False, compactionError=False)
busy = dict(busy=True, blocked=True, busyLock="member")
assert probe.status_samples_fresh({"a": fresh}, {"a": 1})
assert not probe.status_samples_fresh({"a": fresh, "b": busy}, {"a": 1, "b": 1})
assert not probe.status_samples_fresh({"b": busy})

rejections = [
    {"a": dict(fresh, term=2), "b": busy},
    {"a": dict(fresh, churnError="failed"), "b": busy},
    {"a": dict(fresh, compactionError="failed"), "b": busy},
    {"a": dict(fresh, heapLimitMiB=512), "b": busy},
    {"a": dict(fresh, mutualTls=False), "b": busy},
    {"a": fresh, "b": dict(busy, applied=17)},
    {"a": fresh, "b": dict(busy, term=1)},
    {"a": fresh, "b": dict(busy, blocked=False)},
]
for values in rejections:
    try:
        probe.status_samples_fresh(values, {"a": 1, "b": 1})
    except AssertionError:
        pass
    else:
        raise AssertionError(f"Unsafe observation accepted: {values}")
assert probe.status_samples_fresh({"a": dict(fresh, term=2)})  # Cold elections are explicit.
print("OBSERVATION-POLICY-CHECKS-PASSED 12")
