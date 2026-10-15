# SPDX-License-Identifier: Apache-2.0
"""The public tree holds only general things: no home paths, e-mail addresses, real-looking ids, secrets or the code's
own absolute path; every source file carries the SPDX header; LICENSE is the full Apache-2.0 text; AGENTS.md is short.
A private deny list (one regex per line, set MM_PUBLIC_DENY to its path) adds the owner's own names."""
import os
import re
import tempfile
import unittest
from unittest.mock import patch

import mmtest
from mmtest import mmcore

SKIP_DIRS = {"results", "__pycache__", ".git"}
TEXT_EXT = {".py", ".md", ".toml", ".json", ".txt", ".log", ".ndjson", ".sh", ""}
FAKE_UUID = re.compile(r"^([0-9a-f])\1{7}-|^(0123|1111|aaaa|4f1c2d3e)")


def files():
    for d, dirs, names in os.walk(mmtest.CODE):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for n in sorted(names):
            if n == ".git":
                continue
            p = os.path.join(d, n)
            if os.path.splitext(n)[1] in TEXT_EXT:
                yield os.path.relpath(p, mmtest.CODE), open(p, encoding="utf-8", errors="replace").read()


class Public(unittest.TestCase):
    def test_git_metadata_is_skipped_as_file_or_directory(self):
        os.makedirs(mmtest.TMP_BASE, exist_ok=True)
        for directory in (False, True):
            with self.subTest(git_is_directory=directory), tempfile.TemporaryDirectory(dir=mmtest.TMP_BASE) as root:
                git = os.path.join(root, ".git")
                if directory:
                    os.makedirs(git)
                    git = os.path.join(git, "config")
                with open(git, "w") as f:
                    f.write("gitdir: /home/private-user/project\n")
                public = os.path.join(root, "public.txt")
                with open(public, "w") as f:
                    f.write("ordinary content\n")
                with patch.object(mmtest, "CODE", root):
                    self.assertEqual(list(files()), [("public.txt", "ordinary content\n")])
                    self.test_generic_leaks()
                    with open(public, "w") as f:
                        f.write("/home/private-user/project\n")
                    with self.assertRaises(AssertionError):
                        self.test_generic_leaks()

    def test_generic_leaks(self):
        found = []
        for rel, text in files():
            if rel == os.path.join("tests", "test_public.py"):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                for m in re.finditer(r"/(?:Users|home)/([A-Za-z0-9._-]+)", line):
                    if m.group(1) not in ("a", "example", "you", "USER", "name"):
                        found.append("%s:%d home path %s" % (rel, i, m.group(0)))
                for m in re.finditer(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[a-z]{2,})", line):
                    if m.group(1) not in ("example.com", "noreply.example"):
                        found.append("%s:%d e-mail %s" % (rel, i, m.group(0)))
                for m in re.finditer(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", line):
                    if not FAKE_UUID.match(m.group(0)):
                        found.append("%s:%d id %s" % (rel, i, m.group(0)))
                if mmtest.CODE in line or os.path.realpath(mmtest.CODE) in line:
                    found.append("%s:%d the code's own absolute path" % (rel, i))
        self.assertEqual(found, [])

    def test_no_secret_shapes_outside_the_masking_tests(self):
        allowed = {os.path.join("tests", "test_core.py"), os.path.join("tests", "test_supervisor.py"),
                   os.path.join("tests", "test_cli.py"), os.path.join("tests", "gen_vectors.py"), os.path.join("tests", "test_public.py")}
        found = []
        for rel, text in files():
            if rel in allowed or rel.startswith(os.path.join("vectors", "mask")):
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r"gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY", line):
                    found.append("%s:%d" % (rel, i))
        self.assertEqual(found, [])

    def test_private_deny_list(self):
        f = os.environ.get("MM_PUBLIC_DENY")
        if not f:
            self.skipTest("MM_PUBLIC_DENY not set (the owner's private list)")
        pats = [re.compile(l.strip(), re.I) for l in open(f) if l.strip() and not l.startswith("#")]
        self.assertGreater(len(pats), 5)
        found = []
        for rel, text in files():
            for i, line in enumerate(text.splitlines(), 1):
                for p in pats:
                    if p.search(line):
                        found.append("%s:%d /%s/" % (rel, i, p.pattern))
        self.assertEqual(found, [])

    def test_spdx_header_in_every_source_file(self):
        missing = []
        for rel, text in files():
            if rel.endswith(".py") or rel == os.path.join("bin", "mm"):
                if "# SPDX-License-Identifier: Apache-2.0" not in text.splitlines()[:3]:
                    missing.append(rel)
        self.assertEqual(missing, [])

    def test_license_readme_porting_agents(self):
        lic = open(os.path.join(mmtest.CODE, "LICENSE")).read()
        self.assertIn("Apache License", lic)
        self.assertIn("Version 2.0, January 2004", lic)
        self.assertIn("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", lic)
        self.assertIn("END OF TERMS AND CONDITIONS", lic)
        self.assertGreater(len(lic), 10000, "the full text, not a placeholder")
        readme = open(os.path.join(mmtest.CODE, "README.md")).read()
        for part in ("## What", "## Install", "## Status", "## Stop", "## Roll back", "## Profile", "## Settings"):
            self.assertIn(part, readme)
        porting = open(os.path.join(mmtest.CODE, "PORTING.md")).read()
        for part in ("vectors/", "schemas/", "run_vectors.py"):
            self.assertIn(part, porting)
        agents = open(os.path.join(mmtest.CODE, "AGENTS.md")).read().splitlines()
        self.assertLessEqual(len(agents), 60)
        text = "\n".join(agents)
        for part in ("mm status", "mm alerts", "mm explain", "Exit codes", "Never"):
            self.assertIn(part, text)

    def test_glossary_names_every_alert(self):
        import mmalerts
        text = open(os.path.join(mmtest.CODE, "README.md")).read()
        src = open(os.path.join(mmtest.CODE, "core", "mmalerts.py")).read() + \
            open(os.path.join(mmtest.CODE, "adapters", "ad_ci_github.py")).read()
        names = set(re.findall(r'(?:_c|mk)\([^,]+, "([A-Z][A-Z0-9_]+)"', src))
        self.assertGreater(len(names), 30)
        names |= {"SELF_STALE", "SETTINGS_BAD", "SUPERVISOR_ERROR", "STOPPED", "TRIM_DONE", "TRIM_REFUSED", "GUARD_STOP"}
        names -= {"ACTION", "ATTENTION", "INFO", "GREEN", "AMBER", "RED", "STEADY", "UNKNOWN"}
        missing = sorted(n for n in names if "`%s`" % n not in text)
        self.assertEqual(missing, [], "README.md, Glossary: every alert name")


if __name__ == "__main__":
    unittest.main()
