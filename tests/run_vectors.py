#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the Python core against every vector in vectors/<function>/<case>.json.
A vector: {"function", "case", "settings": "base" or absent, "settings_over": {...}, "input": ..., "expected": ...}.
Settings come from vectors/_settings/base.json (a flat dict). Exit 0 when all pass. --list prints counts."""
import json
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
from vector_functions import FUNCTIONS  # noqa: E402

VEC = os.path.join(os.path.dirname(HERE), "vectors")


def load_all():
    base = json.load(open(os.path.join(VEC, "_settings", "base.json")))
    out = []
    for fn in sorted(os.listdir(VEC)):
        if fn.startswith("_") or not os.path.isdir(os.path.join(VEC, fn)):
            continue
        for case in sorted(os.listdir(os.path.join(VEC, fn))):
            if case.endswith(".json"):
                v = json.load(open(os.path.join(VEC, fn, case)))
                s = dict(base)
                s.update(v.get("settings_over") or {})
                out.append((fn, case, v, s))
    return out


def norm(x):
    """JSON round trip: tuples become lists, so Python results compare with the file's values."""
    return json.loads(json.dumps(x))


def main(argv):
    vs = load_all()
    counts, fails = {}, []
    for fn, case, v, s in vs:
        counts[fn] = counts.get(fn, 0) + 1
        try:
            got = norm(FUNCTIONS[fn](v["input"], s))
        except Exception as e:  # a crash is a failure of that vector
            got = "EXCEPTION %r" % e
        if got != v["expected"]:
            fails.append("%s/%s: expected %s got %s" % (fn, case, json.dumps(v["expected"])[:300], json.dumps(got)[:300]))
    if "--list" in argv:
        for k in sorted(counts):
            print("%s=%d" % (k, counts[k]))
    for f in fails:
        print("FAIL " + f)
    print("vectors=%d functions=%d failed=%d" % (len(vs), len(counts), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
