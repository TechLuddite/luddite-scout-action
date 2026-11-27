"""Runs the vendored bin/scout --dir over a checkout and decides pass or fail.

Called by action.yml as python3 -I -S gate.py. Inputs come only from the
environment (INPUT_PATH, INPUT_FAIL_ON, INPUT_FAIL_ON_INCOMPLETE, INPUT_NAME,
INPUT_COMMIT, INPUT_ACCEPTED), never from the command line, so a value can
never become an option. Exit 0 passes, 1 fails the gate, 2 is a usage error.

INPUT_ACCEPTED names a JSON file inside the scanned directory that lists
findings a maintainer has accepted, each with a rule, a path and a reason. An
accepted finding stays in the report and is listed again with its reason, and
it is left out of the fail-on decision. An entry that matches no finding fails
the gate, so the list cannot outlive what it excuses. Only this gate reads the
file. bin/scout ignores it, so a scan of somebody else's repository is never
changed by a file that repository ships.

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
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEVELS = ["info", "low", "medium", "high"]
FAIL_ON = LEVELS + ["never"]
ACCEPTED_MAX_BYTES = 64 * 1024
ACCEPTED_MAX_ENTRIES = 200
ACCEPTED_KEYS = {"rule", "path", "reason"}


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


def read_accepted(root, rel):
    """Returns the entries of the accepted-findings file, or raises ValueError.

    The file comes from the scanned directory, so it is read as data only: a
    relative path with no .. part, no symlink in any part of it, a size limit,
    and a fixed shape with no unknown keys."""
    parts = rel.split("/")
    if rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError("accepted must be a relative path inside the scanned directory.")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            for part in parts[:-1]:
                nxt = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = nxt
            leaf = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=fd)
        finally:
            os.close(fd)
    except OSError:
        raise ValueError(f"accepted file {rel} is missing, or part of its path is a symlink.") from None
    if not stat.S_ISREG(os.fstat(leaf).st_mode):
        os.close(leaf)
        raise ValueError(f"accepted file {rel} is not a regular file.")
    with os.fdopen(leaf, "rb") as fh:
        raw = fh.read(ACCEPTED_MAX_BYTES + 1)
    if len(raw) > ACCEPTED_MAX_BYTES:
        raise ValueError(f"accepted file {rel} is over {ACCEPTED_MAX_BYTES} bytes.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError(f"accepted file {rel} is not valid UTF-8 JSON.") from None
    entries = data.get("accepted") if isinstance(data, dict) and set(data) == {"accepted"} else None
    if not isinstance(entries, list) or len(entries) > ACCEPTED_MAX_ENTRIES:
        raise ValueError(f'accepted file {rel} must be {{"accepted": [...]}} with at most {ACCEPTED_MAX_ENTRIES} entries.')
    seen = set()
    for n, e in enumerate(entries, 1):
        if not isinstance(e, dict) or not set(e) <= ACCEPTED_KEYS or not {"rule", "reason"} <= set(e):
            raise ValueError(f"accepted entry {n} needs rule and reason, may have path, and nothing else.")
        if not all(isinstance(v, str) and v.strip() for v in e.values()):
            raise ValueError(f"accepted entry {n} has an empty or non-text value.")
        key = (e["rule"], e.get("path"))
        if key in seen:
            raise ValueError(f"accepted entry {n} repeats an earlier rule and path.")
        seen.add(key)
    return entries


def split_accepted(report, entries):
    """Returns (accepted, unused): the findings an entry covers, each paired
    with its reason, and the entries that cover nothing. An entry covers the
    findings with the same rule and the same path. An entry with no path
    covers only findings that have no path."""
    by_key = {(e["rule"], e.get("path")): e for e in entries}
    used, accepted = set(), []
    for c in report["checks"]:
        for f in c["findings"]:
            key = (f.get("rule"), f.get("path"))
            if key in by_key:
                used.add(key)
                accepted.append((c["id"], f, by_key[key]["reason"]))
    return accepted, [e for k, e in by_key.items() if k not in used]


def accepted_text(accepted, unused):
    lines = []
    if accepted:
        lines.append(f"Accepted findings, left out of the gate ({len(accepted)}):")
        for cid, f, reason in accepted:
            where = f" {f['path']}" if f.get("path") else ""
            lines.append(f"  {cid} {f['severity'].upper()} {f.get('rule')}{where}: {reason}")
    if unused:
        lines.append(f"Accepted entries that match no finding ({len(unused)}). Remove them:")
        for e in unused:
            lines.append(f"  {e['rule']} {e.get('path', '(no path)')}")
    return "\n".join(lines)


def should_fail(report, fail_on, fail_on_incomplete, accepted=()):
    """A skipped or partial check fails by default: a pull request could
    otherwise pad a file past a read limit to keep it out of the scan.
    Findings in accepted, as split_accepted returns them, are not counted."""
    if fail_on == "never":
        return False
    if fail_on_incomplete and any(c["status"] in ("skipped", "partial") for c in report["checks"]):
        return True
    floor = LEVELS.index(fail_on)
    skip = {id(f) for _, f, _ in accepted}
    return any(LEVELS.index(f["severity"]) >= floor
               for c in report["checks"] for f in c["findings"] if id(f) not in skip)


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
    accepted, unused = [], []
    accepted_path = env.get("INPUT_ACCEPTED") or ""
    if accepted_path:
        try:
            entries = read_accepted(env.get("INPUT_PATH") or ".", accepted_path)
        except ValueError as e:
            print(log_text(text + f"\n\nLuddite Scout: {scout.term_safe(str(e))}"))
            return 2
        accepted, unused = split_accepted(report, entries)
        extra = accepted_text(accepted, unused)
        if extra:
            text += "\n\n" + "\n".join(scout.term_safe(line) for line in extra.splitlines())
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

    failed = should_fail(report, fail_on, fail_on_incomplete, accepted) or (bool(unused) and fail_on != "never")
    verdict = "fails" if failed else "passes"
    print(f"Luddite Scout {verdict} the gate (fail-on: {fail_on}, fail-on-incomplete: {str(fail_on_incomplete).lower()}, "
          f"accepted: {len(accepted)}, unused accepted entries: {len(unused)}).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
