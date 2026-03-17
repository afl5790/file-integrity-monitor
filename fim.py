#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Detects unauthorized additions, modifications, and deletions of files.

Usage:
  python fim.py baseline <directory> [--output baseline.json]
  python fim.py check    <directory> [--baseline baseline.json] [--log changes.log] [--email-to addr]
  python fim.py monitor  <directory> [--baseline baseline.json] [--interval 60] [--log changes.log] [--email-to addr]

Email alerts require FIM_SMTP_PASSWORD env var for the SMTP password.
"""

import argparse
import hashlib
import json
import os
import smtplib
import sys
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


# ── Terminal colors (no deps required) ────────────────────────────────────────

class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def colorize(text: str, *codes: str) -> str:
    if not _supports_color():
        return text
    return "".join(codes) + text + Color.RESET


# ── Core hashing ──────────────────────────────────────────────────────────────

def hash_file(filepath: str) -> str | None:
    """Return the SHA-256 hex digest of a file, or None on read error."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65_536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def scan_directory(directory: str) -> dict[str, str]:
    """Walk *directory* and return {absolute_path: sha256_hex} for every file."""
    result: dict[str, str] = {}
    for path in Path(directory).rglob("*"):
        if path.is_file():
            digest = hash_file(str(path))
            if digest:
                result[str(path)] = digest
    return result


# ── Baseline persistence ───────────────────────────────────────────────────────

def save_baseline(files: dict[str, str], output_path: str) -> None:
    payload = {
        "created": datetime.now().isoformat(),
        "directory": str(Path(output_path).resolve()),
        "file_count": len(files),
        "files": files,
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)


def load_baseline(baseline_path: str) -> dict:
    with open(baseline_path) as f:
        return json.load(f)


# ── Integrity comparison ───────────────────────────────────────────────────────

def compare(baseline_files: dict[str, str], current_files: dict[str, str]) -> dict[str, list[str]]:
    """Return a dict with 'modified', 'added', and 'deleted' file lists."""
    baseline_set = set(baseline_files)
    current_set  = set(current_files)

    modified = [p for p in baseline_set & current_set if baseline_files[p] != current_files[p]]
    added    = sorted(current_set  - baseline_set)
    deleted  = sorted(baseline_set - current_set)

    return {"modified": sorted(modified), "added": added, "deleted": deleted}


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_report(changes: dict[str, list[str]], timestamp: str | None = None) -> None:
    ts    = timestamp or datetime.now().isoformat(timespec="seconds")
    total = sum(len(v) for v in changes.values())

    print(f"\n{colorize(ts, Color.BOLD)}  —  Integrity Check")
    print("─" * 52)

    if total == 0:
        print(colorize("  ✔  No changes detected.", Color.GREEN))
        print("─" * 52)
        return

    icons = {
        "modified": (colorize("~ MODIFIED", Color.YELLOW), Color.YELLOW),
        "added":    (colorize("+ ADDED",    Color.CYAN),   Color.CYAN),
        "deleted":  (colorize("- DELETED",  Color.RED),    Color.RED),
    }

    for category, (label, color) in icons.items():
        files = changes[category]
        if files:
            print(f"\n  {label}  ({len(files)})")
            for f in files:
                print(colorize(f"    {f}", color))

    print(f"\n  Total changes: {colorize(str(total), Color.BOLD)}")
    print("─" * 52)


def log_changes(changes: dict[str, list[str]], log_path: str) -> None:
    total = sum(len(v) for v in changes.values())
    if total == 0:
        return
    ts = datetime.now().isoformat(timespec="seconds")
    with open(log_path, "a") as f:
        f.write(f"\n[{ts}]\n")
        for category, files in changes.items():
            for path in files:
                f.write(f"  {category.upper():8s}  {path}\n")


# ── Email alerting ────────────────────────────────────────────────────────────

def build_email_body(changes: dict[str, list[str]], directory: str, ts: str) -> tuple[str, str]:
    """Return (plain_text, html) email bodies describing the changes."""
    total = sum(len(v) for v in changes.values())

    # ── plain text ──
    lines = [
        f"FIM ALERT — {total} change(s) detected",
        f"Directory : {directory}",
        f"Timestamp : {ts}",
        "",
    ]
    labels = {"modified": "~ MODIFIED", "added": "+ ADDED", "deleted": "- DELETED"}
    for category, label in labels.items():
        if changes[category]:
            lines.append(f"{label} ({len(changes[category])}):")
            for f in changes[category]:
                lines.append(f"  {f}")
            lines.append("")
    plain = "\n".join(lines)

    # ── html ──
    colors = {"modified": "#e6a817", "added": "#17a2b8", "deleted": "#dc3545"}
    rows = ""
    for category, color in colors.items():
        for f in changes[category]:
            tag = category.upper()
            rows += (
                f'<tr><td style="color:{color};font-weight:bold;padding:2px 8px">{tag}</td>'
                f'<td style="font-family:monospace;padding:2px 8px">{f}</td></tr>'
            )
    html = f"""<html><body>
<h2 style="color:#dc3545">&#x26A0; FIM Alert</h2>
<p><b>Directory:</b> {directory}<br>
   <b>Timestamp:</b> {ts}<br>
   <b>Total changes:</b> {total}</p>
<table border="0" cellpadding="0" cellspacing="4">{rows}</table>
</body></html>"""

    return plain, html


def send_email_alert(changes: dict[str, list[str]], directory: str, args) -> None:
    """Send an SMTP alert if changes were detected. Reads password from FIM_SMTP_PASSWORD."""
    total = sum(len(v) for v in changes.values())
    if total == 0:
        return

    password = os.environ.get("FIM_SMTP_PASSWORD", "")
    ts = datetime.now().isoformat(timespec="seconds")

    plain, html = build_email_body(changes, directory, ts)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[FIM ALERT] {total} change(s) in {directory}"
    msg["From"]    = args.email_from
    msg["To"]      = args.email_to
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))

    try:
        with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if args.smtp_user:
                server.login(args.smtp_user, password)
            server.sendmail(args.email_from, args.email_to, msg.as_string())
        print(f"[+] Alert email sent → {args.email_to}")
    except Exception as exc:
        print(colorize(f"[-] Failed to send email: {exc}", Color.RED), file=sys.stderr)


def _add_email_args(parser: argparse.ArgumentParser) -> None:
    """Attach the shared email flags to a subcommand parser."""
    g = parser.add_argument_group("email alerts (optional)")
    g.add_argument("--email-to",   metavar="ADDR", help="Send alerts to this address")
    g.add_argument("--email-from", metavar="ADDR", default="fim@localhost",
                   help="Sender address (default: fim@localhost)")
    g.add_argument("--smtp-host",  metavar="HOST", default="smtp.gmail.com",
                   help="SMTP server (default: smtp.gmail.com)")
    g.add_argument("--smtp-port",  metavar="PORT", type=int, default=587,
                   help="SMTP port (default: 587)")
    g.add_argument("--smtp-user",  metavar="USER",
                   help="SMTP username (password via FIM_SMTP_PASSWORD env var)")


# ── CLI commands ───────────────────────────────────────────────────────────────

def cmd_baseline(args) -> None:
    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        sys.exit(f"[-] Not a directory: {directory}")

    print(f"[*] Scanning {directory} ...")
    files = scan_directory(directory)
    save_baseline(files, args.output)
    print(colorize(f"[+] Baseline saved → {args.output}  ({len(files)} files hashed)", Color.GREEN))


def cmd_check(args) -> None:
    if not os.path.exists(args.baseline):
        sys.exit(f"[-] Baseline not found: {args.baseline}\n    Run 'baseline' first.")

    data = load_baseline(args.baseline)
    directory = os.path.abspath(args.directory)

    print(f"[*] Checking {directory}")
    print(f"[*] Baseline created: {data['created']}")

    current = scan_directory(directory)
    changes = compare(data["files"], current)
    print_report(changes)

    if args.log:
        log_changes(changes, args.log)
        if sum(len(v) for v in changes.values()):
            print(f"[*] Changes logged → {args.log}")

    if args.email_to:
        send_email_alert(changes, directory, args)

    # Exit code 1 if changes were found (useful in scripts/CI)
    if sum(len(v) for v in changes.values()):
        sys.exit(1)


def cmd_monitor(args) -> None:
    if not os.path.exists(args.baseline):
        sys.exit(f"[-] Baseline not found: {args.baseline}\n    Run 'baseline' first.")

    data = load_baseline(args.baseline)
    directory = os.path.abspath(args.directory)

    print(colorize(f"[*] Monitoring  {directory}", Color.BOLD))
    print(f"[*] Baseline:   {data['created']}")
    print(f"[*] Interval:   {args.interval}s")
    if args.log:
        print(f"[*] Log file:   {args.log}")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        while True:
            current = scan_directory(directory)
            changes = compare(data["files"], current)
            print_report(changes)
            if args.log:
                log_changes(changes, args.log)
            if args.email_to:
                send_email_alert(changes, directory, args)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped.")


# ── Entry point ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — detect unauthorized file changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  Create a baseline of your home directory:
    python fim.py baseline ~/documents --output docs_baseline.json

  One-shot integrity check:
    python fim.py check ~/documents --baseline docs_baseline.json

  Continuous monitoring every 30 seconds, with a log:
    python fim.py monitor ~/documents --baseline docs_baseline.json --interval 30 --log fim.log

  Monitor and email alerts via Gmail:
    export FIM_SMTP_PASSWORD="your-app-password"
    python fim.py monitor ~/documents --baseline docs_baseline.json \\
        --email-to you@example.com --email-from sender@gmail.com \\
        --smtp-user sender@gmail.com
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # baseline
    p = sub.add_parser("baseline", help="Create a new file-hash baseline")
    p.add_argument("directory", help="Directory to baseline")
    p.add_argument("--output", default="baseline.json", metavar="FILE",
                   help="Where to save the baseline (default: baseline.json)")

    # check
    p = sub.add_parser("check", help="Compare current state to baseline")
    p.add_argument("directory", help="Directory to check")
    p.add_argument("--baseline", default="baseline.json", metavar="FILE",
                   help="Baseline file to compare against (default: baseline.json)")
    p.add_argument("--log", metavar="FILE", help="Append changes to this log file")
    _add_email_args(p)

    # monitor
    p = sub.add_parser("monitor", help="Continuously poll for changes")
    p.add_argument("directory", help="Directory to monitor")
    p.add_argument("--baseline", default="baseline.json", metavar="FILE",
                   help="Baseline file (default: baseline.json)")
    p.add_argument("--interval", type=int, default=60, metavar="SECONDS",
                   help="Seconds between checks (default: 60)")
    p.add_argument("--log", metavar="FILE", help="Append alerts to this log file")
    _add_email_args(p)

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "baseline": cmd_baseline,
        "check":    cmd_check,
        "monitor":  cmd_monitor,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
