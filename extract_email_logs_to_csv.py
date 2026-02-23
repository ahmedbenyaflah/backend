#!/usr/bin/env python3
"""
Extract QUEUE, DEQUEUER, and SMTP log lines from CommuniGate Pro email system logs
and output a single CSV file sorted by timestamp.

Handles large files (100MB+) by reading in batches.
"""

import csv
import re
import os
from pathlib import Path
from datetime import datetime

# Log folders to process (FES + mapped servers)
SOURCE_SERVERS = {"FES01", "FES02", "VIP01", "VIP02", "GP01", "GP02", "ML01", "ML02", "MX01", "MX02"}

# Regex patterns for log line types
# QUEUE: "2 QUEUE([1846258457]) from <contact@topformation.net>, 6910 bytes" or "2 QUEUE([1846258457]) enqueued"
QUEUE_FROM_RE = re.compile(
    r"^\s*(\d{2}:\d{2}:\d{2}\.\d{3})\s+\d\s+QUEUE\(\[(\d+)\]\)\s+from\s+<([^>]*)>,\s+\d+\s+bytes",
    re.IGNORECASE,
)
QUEUE_ENQUEUED_RE = re.compile(
    r"^\s*(\d{2}:\d{2}:\d{2}\.\d{3})\s+\d\s+QUEUE\(\[(\d+)\]\)\s+enqueued",
    re.IGNORECASE,
)

# DEQUEUER: "2 DEQUEUER [1846258457] LOCAL(m.dridi@palmaalu.com)m.dridi@palmaalu.com delivered: ..."
# or "2 DEQUEUER [1846258469] SMTP([41.224.252.12])ferid.abbas@setcar.com.tn relayed: ..."
# or "1 DEQUEUER [1846411992] SMTP(*)alerts@ironport.com failed: ..."
# or "2 DEQUEUER [113425759] LOCAL(postmaster)<root> delivered: ..."
DEQUEUER_RE = re.compile(
    r"^\s*(\d{2}:\d{2}:\d{2}\.\d{3})\s+\d\s+DEQUEUER\s+\[(\d+)\]\s+"
    r"(?:LOCAL\([^)]*\)|SMTP\([^)]*\)|SYSTEM\([^)]*\))([^\s]+)\s+"
    r"(delivered|relayed|failed):",
    re.IGNORECASE,
)

# SMTP: "2 SMTP-747258(*) [1846411893] sent [10.46.2.61]:57726 -> [10.46.96.20]:25, got:250 113457091 message accepted for delivery"
# or "2 SMTP-011138(azur.tn) [120798517] sent [197.26.11.133]:37451 -> [52.101.68.12]:25, got:250 2.6.0 ..."
SMTP_SENT_FULL_RE = re.compile(
    r"^\s*(\d{2}:\d{2}:\d{2}\.\d{3})\s+\d\s+(SMTP-\d+\([^)]*\))\s+\[(\d+)\]\s+sent\s+.*",
    re.IGNORECASE,
)
# Only match got:250 when followed by numeric id + "message" (internal relay), not "2.6.0" (external SMTP)
GOT_250_RE = re.compile(r"got:250\s+(\d+)\s+message")
GOT_250_SUCCESS_RE = re.compile(r"got:250", re.IGNORECASE)


def extract_date_from_filename(filename: str) -> str:
    """Extract YYYY-MM-DD from log filename (e.g. 2026-01-27.log or 2026-01-27_23-12.log)."""
    match = re.match(r"(\d{4}-\d{2}-\d{2})", filename)
    return match.group(1) if match else ""


def parse_queue_line(line: str, date_str: str) -> dict | None:
    """Parse QUEUE line. Returns row dict or None if not a QUEUE from/enqueued line we want."""
    m = QUEUE_FROM_RE.search(line)
    if m:
        ts = f"{date_str} {m.group(1)}" if date_str else m.group(1)
        return {
            "timestamp": ts,
            # QUEUE lines have qid, but no delivery_id
            "qid": m.group(2),
            "delivery_id": "",
            "sender": m.group(3).strip(),
            "recipient": "",
            "log_type": "QUEUE",
            "success": "true",  # Enqueue is a success step
            "source_server": "",
            "message": line.strip(),
        }
    m = QUEUE_ENQUEUED_RE.search(line)
    if m:
        ts = f"{date_str} {m.group(1)}" if date_str else m.group(1)
        return {
            "timestamp": ts,
            "qid": m.group(2),
            "delivery_id": "",
            "sender": "",
            "recipient": "",
            "log_type": "QUEUE",
            "success": "true",
            "source_server": "",
            "message": line.strip(),
        }
    return None


def parse_dequeuer_line(line: str, date_str: str) -> dict | None:
    """Parse DEQUEUER line."""
    if " DEQUEUER " not in line:
        return None
    m = DEQUEUER_RE.search(line)
    if m:
        ts = f"{date_str} {m.group(1)}" if date_str else m.group(1)
        status = m.group(4).lower()
        success = "true" if status in ("delivered", "relayed") else "false"
        recipient = (m.group(3) or "").strip().strip("<>")
        return {
            "timestamp": ts,
            # DEQUEUER lines have qid, but no delivery_id
            "qid": m.group(2),
            "delivery_id": "",
            "sender": "",
            "recipient": recipient,
            "log_type": "DEQUEUER",
            "success": success,
            "source_server": "",
            "message": line.strip(),
        }
    # Fallback: simpler DEQUEUER pattern
    dequeuer_match = re.search(
        r"^\s*(\d{2}:\d{2}:\d{2}\.\d{3})\s+\d\s+DEQUEUER\s+\[(\d+)\]\s+(.+)",
        line,
        re.IGNORECASE,
    )
    if dequeuer_match:
        ts = f"{date_str} {dequeuer_match.group(1)}" if date_str else dequeuer_match.group(1)
        rest = dequeuer_match.group(3)
        success = "true" if ("delivered" in rest or "relayed" in rest) else "false"
        # Try to extract recipient: LOCAL(x)x or SMTP(dom)x
        recip_match = re.search(r"(?:LOCAL|SMTP|SYSTEM)\([^)]*\)([^\s]+)", rest)
        recipient = recip_match.group(1).strip() if recip_match else ""
        return {
            "timestamp": ts,
            "qid": dequeuer_match.group(2),
            "delivery_id": "",
            "sender": "",
            "recipient": recipient,
            "log_type": "DEQUEUER",
            "success": success,
            "source_server": "",
            "message": line.strip(),
        }
    return None


def parse_smtp_line(line: str, date_str: str) -> dict | None:
    """Parse SMTP sent line (delivery attempt with got:)."""
    if " SMTP-" not in line or " sent " not in line:
        return None
    m = SMTP_SENT_FULL_RE.search(line)
    if not m:
        return None
    ts = f"{date_str} {m.group(1)}" if date_str else m.group(1)
    qid = m.group(3)
    success = "true" if GOT_250_SUCCESS_RE.search(line) else "false"
    delivery_id = ""
    did_match = GOT_250_RE.search(line)
    if did_match:
        delivery_id = did_match.group(1)
    return {
        "timestamp": ts,
        "qid": qid,
        "delivery_id": delivery_id,
        "sender": "",
        "recipient": "",
        "log_type": "SMTP",
        "success": success,
        "source_server": "",
        "message": line.strip(),
    }


def read_log_file_batched(filepath: Path, batch_size: int = 1024 * 1024) -> list[str]:
    """Read log file in batches. Returns lines (handles possible multi-line)."""
    lines = []
    buffer = ""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        while True:
            chunk = f.read(batch_size)
            if not chunk:
                break
            buffer += chunk
            parts = buffer.split("\n")
            buffer = parts.pop()  # Keep incomplete line in buffer
            lines.extend(parts)
        if buffer:
            lines.append(buffer)
    return lines


def process_log_folder(log_root: Path) -> list[dict]:
    """Process all log files under log_root, return list of row dicts."""
    rows = []
    log_root = Path(log_root)

    for server_dir in sorted(log_root.iterdir()):
        if not server_dir.is_dir():
            continue
        source_server = server_dir.name
        if source_server not in SOURCE_SERVERS:
            continue

        for log_file in sorted(server_dir.glob("*.log")):
            date_str = extract_date_from_filename(log_file.name)
            if not date_str:
                continue

            try:
                file_lines = read_log_file_batched(log_file)
            except Exception as e:
                print(f"Warning: Could not read {log_file}: {e}")
                continue

            for line in file_lines:
                if not line.strip():
                    continue
                row = None
                if " QUEUE(" in line and (" from " in line or " enqueued" in line):
                    row = parse_queue_line(line, date_str)
                elif " DEQUEUER " in line:
                    row = parse_dequeuer_line(line, date_str)
                elif " SMTP-" in line and " sent " in line:
                    row = parse_smtp_line(line, date_str)

                if row:
                    row["source_server"] = source_server
                    rows.append(row)

    return rows


def sort_rows_by_timestamp(rows: list[dict]) -> list[dict]:
    """Sort rows by timestamp. Handles various timestamp formats."""
    def parse_ts(r):
        ts = r.get("timestamp", "")
        try:
            # Try ISO-like: 2026-01-27 00:00:00.019
            if " " in ts and len(ts) > 10:
                return datetime.strptime(ts[:26], "%Y-%m-%d %H:%M:%S.%f")
            # Time only: 00:00:00.019 - use epoch date
            if "." in ts and len(ts) <= 12:
                return datetime.strptime(ts, "%H:%M:%S.%f")
        except ValueError:
            pass
        return datetime.min

    return sorted(rows, key=parse_ts)


def main():
    log_root = Path(__file__).parent / "Log-CG"
    if not log_root.exists():
        log_root = Path("Log-CG")
    if not log_root.exists():
        print(f"Error: Log folder not found. Expected: {log_root}")
        return 1

    print(f"Processing logs from: {log_root}")
    rows = process_log_folder(log_root)
    print(f"Extracted {len(rows)} log lines")

    rows = sort_rows_by_timestamp(rows)

    output_path = Path(__file__).parent / "email_logs_extracted.csv"
    fieldnames = [
        "timestamp",
        "qid",
        "delivery_id",
        "sender",
        "recipient",
        "log_type",
        "success",
        "source_server",
        "message",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to: {output_path}")
    return 0


if __name__ == "__main__":
    exit(main())
