#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A small queue launcher for the tests (the fifo-gates format): `launcher.py [--exclusive] -- CMD...`.
A shared call holds `.slot.1`; an exclusive call needs QUEUE_EXCLUSIVE_OK=1 and holds `.gate.lock` and every slot.
A waiting call holds a ticket in queue/. It writes one history row when the command ends."""
import fcntl
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))


def main(argv):
    excl = argv[:1] == ["--exclusive"]
    if excl:
        argv = argv[1:]
        if os.environ.get("QUEUE_EXCLUSIVE_OK") != "1":
            print("exclusive calls need QUEUE_EXCLUSIVE_OK=1")
            return 2
    if argv[:1] != ["--"]:
        return 2
    cmd = argv[1:]
    os.makedirs(os.path.join(HERE, "queue"), exist_ok=True)
    ticket = os.path.join(HERE, "queue", "%d-%d" % (time.time_ns(), os.getpid()))
    tf = open(ticket, "w")
    fcntl.flock(tf, fcntl.LOCK_EX)
    tf.write("%s %d %s\n" % ("X" if excl else "S", os.getpid(), " ".join(cmd)[:80]))
    tf.flush()
    t0 = time.time()
    names = [".gate.lock"] + [".slot.%d" % k for k in range(1, 4)] if excl else [".slot.1"]
    held = []
    for n in names:
        f = open(os.path.join(HERE, n), "a+")
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        f.truncate()
        f.write("%s %d %s\n" % ("X" if excl else "S", os.getpid(), " ".join(cmd)[:80]))
        f.flush()
        held.append(f)
    wait = time.time() - t0
    tf.close()
    os.remove(ticket)
    rc = subprocess.call(cmd)
    run = time.time() - t0 - wait
    with open(os.path.join(HERE, "history.log"), "a") as h:
        h.write("%s\t%d\t%s\twait=%d\trun=%d\trc=%d\tmem=steady\tcwd=%s\t%s\t%s\n" % (
            time.strftime("%Y-%m-%dT%H:%M:%S"), os.getpid(), "X" if excl else "S", wait, run, rc, os.getcwd(),
            cmd[0], " ".join(cmd)))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
