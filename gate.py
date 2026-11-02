"""Runs the vendored bin/scout --dir over a checkout and decides pass or fail.

Called by action.yml as python3 -I -S gate.py. Inputs come only from the
environment (INPUT_PATH, INPUT_FAIL_ON, INPUT_FAIL_ON_INCOMPLETE, INPUT_NAME,
INPUT_COMMIT), never from the command line, so a value can never become an
option. Exit 0 passes, 1 fails the gate, 2 is a usage error.

Report text is printed between ::stop-commands:: and a fresh random token, so
nothing the scanned repository controls (a file name, a snippet) can issue a
workflow command.
"""
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEVELS = ["info", "low", "medium", "high"]
FAIL_ON = LEVELS + ["never"]


def load_scout():
    loader = importlib.machinery.SourceFileLoader("scout", os.path.join(HERE, "bin", "scout"))
    spec = importlib.util.spec_from_loader("scout", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def parse_fail_on(value):
    v = value.lower()
    if v not in FAIL_ON:
        raise ValueError(f"fail-on must be one of {', '.join(FAIL_ON)}.")
    return v


def parse_bool(value, name):
    v = value.strip().lower()
    if v not in ("true", "false"):
        raise ValueError(f"{name} must be true or false.")
    return v == "true"


def should_fail(report, fail_on, fail_on_incomplete):
    """A skipped or partial check fails by default: a pull request could
    otherwise pad a file past a read limit to keep it out of the scan."""
    if fail_on == "never":
        return False
    if fail_on_incomplete and any(c["status"] in ("skipped", "partial") for c in report["checks"]):
        return True
    floor = LEVELS.index(fail_on)
    return any(LEVELS.index(f["severity"]) >= floor for c in report["checks"] for f in c["findings"])


def log_text(text):
    token = secrets.token_hex(32)
    while token in text:
        token = secrets.token_hex(32)
    body = "\n".join("  " + line for line in text.splitlines())
    return f"::stop-commands::{token}\n{body}\n::{token}::"


def summary_markdown(title, body):
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"## {title}\n\n{fence}\n{body}\n{fence}\n"


def main():
    env = os.environ
    try:
        fail_on = parse_fail_on(env.get("INPUT_FAIL_ON", "high"))
        fail_on_incomplete = parse_bool(env.get("INPUT_FAIL_ON_INCOMPLETE", "true"), "fail-on-incomplete")
    except ValueError as e:
        print(f"Luddite Scout: {e}")
        return 2
    scout = load_scout()
    try:
        report = scout.scan_dir(env.get("INPUT_PATH") or ".", env.get("INPUT_NAME") or None, env.get("INPUT_COMMIT") or None)
    except (ValueError, scout.ScanError) as e:
        print(log_text(f"Luddite Scout: {scout.term_safe(str(e))}"))
        return 2
    text = scout.format_text(report)
    print(log_text(text))

    out = env.get("SCOUT_REPORT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(scout.bounded_json(report))
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(summary_markdown("Luddite Scout", text))
        except OSError:
            pass

    failed = should_fail(report, fail_on, fail_on_incomplete)
    verdict = "fails" if failed else "passes"
    print(f"Luddite Scout {verdict} the gate (fail-on: {fail_on}, fail-on-incomplete: {str(fail_on_incomplete).lower()}).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
