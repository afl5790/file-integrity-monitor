# File Integrity Monitor (FIM)

A command-line tool that detects unauthorized additions, modifications, and deletions of files using SHA-256 hashing — similar in concept to [Tripwire](https://en.wikipedia.org/wiki/Open_Source_Tripwire) and [AIDE](https://aide.github.io/).

Built with Python's standard library only — no dependencies to install.

---

## Features

- **SHA-256 hashing** of every file in a monitored directory
- Detects **modified**, **added**, and **deleted** files
- Three modes: one-shot baseline, one-shot check, continuous monitoring
- **Email alerts** via SMTP when changes are found (plain text + HTML)
- Append-only **log file** for audit trails
- Exits with code `1` on changes — integrates with shell scripts and CI pipelines

---

## Usage

### 1. Create a baseline

Scan a directory and save a snapshot of all file hashes.

```bash
python fim.py baseline ~/documents --output docs_baseline.json
```

### 2. Check integrity

Compare the current state of a directory against the baseline.

```bash
python fim.py check ~/documents --baseline docs_baseline.json
```

Example output:

```
2026-03-17T16:11:53  —  Integrity Check
────────────────────────────────────────────────────

  ~ MODIFIED  (1)
    /Users/alice/documents/report.docx

  - DELETED  (1)
    /Users/alice/documents/notes.txt

  Total changes: 2
────────────────────────────────────────────────────
```

### 3. Monitor continuously

Poll a directory on a set interval and alert on any changes.

```bash
python fim.py monitor ~/documents \
    --baseline docs_baseline.json \
    --interval 60 \
    --log fim.log
```

---

## Email Alerts

Pass SMTP credentials to receive an email whenever changes are detected. The password is read from the `FIM_SMTP_PASSWORD` environment variable — never passed as a CLI argument.

```bash
export FIM_SMTP_PASSWORD="your-app-password"

python fim.py monitor ~/documents \
    --baseline docs_baseline.json \
    --email-to alerts@example.com \
    --email-from sender@gmail.com \
    --smtp-user sender@gmail.com
```

| Flag | Default | Description |
|---|---|---|
| `--email-to` | — | Recipient address (required to enable alerts) |
| `--email-from` | `fim@localhost` | Sender address |
| `--smtp-host` | `smtp.gmail.com` | SMTP server |
| `--smtp-port` | `587` | SMTP port (STARTTLS) |
| `--smtp-user` | — | SMTP username |

> **Gmail users:** Generate an [App Password](https://support.google.com/accounts/answer/185833) rather than using your account password.

---

## Options reference

```
python fim.py baseline <directory> [--output FILE]
python fim.py check    <directory> [--baseline FILE] [--log FILE] [--email-to ADDR ...]
python fim.py monitor  <directory> [--baseline FILE] [--interval SECONDS] [--log FILE] [--email-to ADDR ...]
```

---

## How it works

1. **Baseline** — walks the target directory recursively and computes a SHA-256 digest for every file. Results are stored in a JSON snapshot with a creation timestamp.
2. **Check** — rescans the directory and compares digests against the snapshot. Any path whose hash changed is flagged as *modified*; paths present only in the snapshot are *deleted*; paths present only in the current scan are *added*.
3. **Monitor** — runs the check in a loop, sleeping `--interval` seconds between iterations. Sends an email alert and/or appends to the log file whenever changes are found.
