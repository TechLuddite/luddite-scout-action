"""Tests for gate.py, the step that runs bin/scout --dir and decides pass or fail.

    python3 -m unittest discover -s test
"""
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("gate", ROOT / "gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def report(*checks):
    return {"tool": "luddite-scout", "version": "0.4.0", "repository": "o/r", "commit": None,
            "api": {"calls": 0, "remaining": None, "limit": None, "authenticated": False, "tokenRejected": False, "local": True},
            "checks": [{"id": cid, "name": cid, "status": status, "notes": [], "findings": [{"severity": s, "title": f"t{i}", "rule": "S4.unpinned-action"} for i, s in enumerate(sevs)]}
                       for cid, status, sevs in checks]}


class Threshold(unittest.TestCase):
    def test_fail_on_levels(self):
        r = report(("S4", "ran", ["medium", "low"]))
        self.assertTrue(gate.should_fail(r, "medium", True))
        self.assertTrue(gate.should_fail(r, "low", True))
        self.assertTrue(gate.should_fail(r, "info", True))
        self.assertFalse(gate.should_fail(r, "high", True))
        self.assertFalse(gate.should_fail(r, "never", True))

    def test_invalid_fail_on_is_rejected(self):
        for bad in ("", "HIGH ", "critical", "high;rm"):
            with self.assertRaises(ValueError, msg=bad):
                gate.parse_fail_on(bad)
        self.assertEqual(gate.parse_fail_on("High"), "high")

    def test_incomplete_check_fails_unless_allowed(self):
        for status in ("skipped", "partial"):
            r = report(("S4", status, []))
            self.assertTrue(gate.should_fail(r, "high", True), status)
            self.assertFalse(gate.should_fail(r, "high", False), status)
            self.assertFalse(gate.should_fail(r, "never", True), status)

    def test_not_applicable_does_not_fail(self):
        r = report(("S1", "not-applicable", []), ("S3", "ran", ["low"]))
        self.assertFalse(gate.should_fail(r, "high", True))


class Accepted(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, value, name=".scout-accepted.json"):
        (self.root / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
        return gate.read_accepted(str(self.root), name)

    def sudo_report(self):
        r = report(("S7", "ran", ["high", "high", "low"]))
        a, b, c = r["checks"][0]["findings"]
        a.update(rule="S7.sudo", path="tools/install.py")
        b.update(rule="S7.sudo", path="bin/other")
        c.update(rule="S7.no-preview")
        return r

    def test_accepted_finding_is_not_counted(self):
        r = self.sudo_report()
        entries = self.write({"accepted": [{"rule": "S7.sudo", "path": "tools/install.py", "reason": "root helper"}]})
        accepted, unused = gate.split_accepted(r, entries)
        self.assertEqual([(cid, f["path"], why) for cid, f, why in accepted], [("S7", "tools/install.py", "root helper")])
        self.assertEqual(unused, [])
        self.assertTrue(gate.should_fail(r, "high", True, accepted), "the same rule in another file still fails")
        entries.append({"rule": "S7.sudo", "path": "bin/other", "reason": "also a helper"})
        accepted, _ = gate.split_accepted(r, entries)
        self.assertFalse(gate.should_fail(r, "high", True, accepted))
        self.assertTrue(gate.should_fail(r, "low", True, accepted))

    def test_entry_without_path_covers_only_pathless_findings(self):
        r = self.sudo_report()
        accepted, unused = gate.split_accepted(r, [{"rule": "S7.sudo", "reason": "x"}, {"rule": "S7.no-preview", "reason": "y"}])
        self.assertEqual([f["rule"] for _, f, _ in accepted], ["S7.no-preview"])
        self.assertEqual([e["rule"] for e in unused], ["S7.sudo"])

    def test_accepted_does_not_excuse_an_incomplete_check(self):
        r = report(("S7", "partial", ["high"]))
        r["checks"][0]["findings"][0].update(path="a")
        accepted, _ = gate.split_accepted(r, [{"rule": "S4.unpinned-action", "path": "a", "reason": "x"}])
        self.assertTrue(gate.should_fail(r, "high", True, accepted))

    def test_malformed_files_are_rejected(self):
        ok = {"rule": "S7.sudo", "path": "a", "reason": "r"}
        for bad in ("not json", [], {"accepted": {}}, {"accepted": [], "more": 1}, {"accepted": ["x"]},
                    {"accepted": [{"rule": "S7.sudo"}]}, {"accepted": [dict(ok, reason="  ")]},
                    {"accepted": [dict(ok, line=3)]}, {"accepted": [dict(ok, path=1)]}, {"accepted": [ok, ok]},
                    {"accepted": [dict(ok, path=str(i)) for i in range(gate.ACCEPTED_MAX_ENTRIES + 1)]},
                    "{\"accepted\": []}" + " " * gate.ACCEPTED_MAX_BYTES):
            with self.assertRaises(ValueError, msg=str(bad)[:60]):
                self.write(bad)

    def test_path_must_stay_inside_and_follow_no_symlink(self):
        self.write({"accepted": []})
        (self.root / "sub").mkdir()
        os.symlink(self.root / ".scout-accepted.json", self.root / "link.json")
        os.symlink(self.root, self.root / "sub" / "up")
        for bad in ("/etc/passwd", "../x.json", "sub/../.scout-accepted.json", "", "link.json",
                    "sub/up/.scout-accepted.json", "missing.json", "sub"):
            with self.assertRaises(ValueError, msg=bad):
                gate.read_accepted(str(self.root), bad)


class Output(unittest.TestCase):
    def test_log_is_wrapped_in_stop_commands(self):
        body = "::add-mask::x\n  ##[error]y\nok"
        out = gate.log_text(body)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("::stop-commands::"), lines[0])
        token = lines[0].split("::")[2]
        self.assertRegex(token, r"^[0-9a-f]{32,}$")
        self.assertEqual(lines[-1], f"::{token}::")
        self.assertNotIn(token, body)
        self.assertNotEqual(token, gate.log_text(body).splitlines()[0].split("::")[2])

    def test_summary_fence_is_longer_than_any_backtick_run(self):
        body = "a ```` b"
        md = gate.summary_markdown("Luddite Scout", body)
        fence = md.splitlines()[2]
        self.assertTrue(set(fence) == {"`"} and len(fence) > 4, fence)
        self.assertTrue(md.rstrip().endswith(fence))


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name) / "repo"
        (self.root / ".gitea" / "workflows").mkdir(parents=True)
        (self.root / ".gitea" / "workflows" / "ci.yml").write_text(
            "on: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"${{ gitea.event.pull_request.title }}\"\n", encoding="utf-8")
        self.summary = pathlib.Path(self.tmp.name) / "summary.md"
        self.out_json = pathlib.Path(self.tmp.name) / "report.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_gate(self, fail_on, summary=True, accepted=""):
        env = {"INPUT_PATH": str(self.root), "INPUT_FAIL_ON": fail_on, "INPUT_NAME": "o/r", "INPUT_ACCEPTED": accepted,
               "INPUT_COMMIT": "", "INPUT_FAIL_ON_INCOMPLETE": "true", "SCOUT_REPORT": str(self.out_json)}
        if summary:
            env["GITHUB_STEP_SUMMARY"] = str(self.summary)
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(out):
            code = gate.main()
        return code, out.getvalue()

    def test_high_finding_fails_at_high(self):
        code, log = self.run_gate("high")
        self.assertEqual(code, 1)
        self.assertIn("Untrusted input expanded directly into a script", log)
        self.assertIn("Untrusted input", self.summary.read_text(encoding="utf-8"))
        self.assertEqual(json.loads(self.out_json.read_text(encoding="utf-8"))["repository"], "o/r")

    def test_never_passes_with_findings(self):
        self.assertEqual(self.run_gate("never")[0], 0)

    def test_no_summary_file_is_fine(self):
        self.assertEqual(self.run_gate("never", summary=False)[0], 0)

    def test_oversized_workflow_fails_by_default(self):
        (self.root / ".gitea" / "workflows" / "ci.yml").write_text("on: pull_request\n" + "#" * 1_100_000 + "\n", encoding="utf-8")
        self.assertEqual(self.run_gate("high")[0], 1)

    def accept(self, *entries):
        (self.root / "ok.json").write_text(json.dumps({"accepted": list(entries)}), encoding="utf-8")
        return self.run_gate("high", accepted="ok.json")

    def test_accepted_finding_passes_and_is_still_reported(self):
        self.assertEqual(self.run_gate("high")[0], 1)
        rule = json.loads(self.out_json.read_text(encoding="utf-8"))["checks"][3]["findings"][0]["rule"]
        code, log = self.accept({"rule": rule, "path": ".gitea/workflows/ci.yml", "reason": "fixture ::error::x"})
        self.assertEqual(code, 0, log)
        self.assertIn("Untrusted input expanded directly into a script", log)
        self.assertIn("Accepted findings, left out of the gate (1):", log)
        self.assertIn("fixture ::error::x", log.split("::stop-commands::")[1])
        self.assertIn("Accepted findings", self.summary.read_text(encoding="utf-8"))
        self.assertEqual(len(json.loads(self.out_json.read_text(encoding="utf-8"))["checks"][3]["findings"]), 1)

    def test_unused_accepted_entry_fails(self):
        code, log = self.accept({"rule": "S7.sudo", "path": "gone.py", "reason": "was a helper"})
        self.assertEqual(code, 1)
        self.assertIn("match no finding (1)", log)

    def test_unreadable_accepted_file_is_a_usage_error(self):
        code, log = self.run_gate("high", accepted="missing.json")
        self.assertEqual(code, 2)
        self.assertIn("missing.json", log)

    def test_bad_input_is_a_usage_error(self):
        code, log = self.run_gate("critical")
        self.assertEqual(code, 2)
        self.assertIn("fail-on", log)


if __name__ == "__main__":
    unittest.main()
