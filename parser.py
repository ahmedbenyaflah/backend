"""
Log parsing logic for SMTP/mail flow across distributed servers (FES*, VIP*, GP*, ML*).
Traces email lifecycle: front-end validation, queue ID tracking, recursive multi-server routing.
Uses ripgrep (rg) for search when available; falls back to in-process Python regex search if rg
is not installed. All date handling assumes YYYY-MM-DD after normalization; time is local (no TZ).
"""
import logging
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# Module-level logger for parser operations (see NOTES: logging.getLogger).
log = logging.getLogger(__name__)


def _normalize_date(date_str: Optional[str]) -> Optional[str]:
    """
    Normalize a date string to canonical YYYY-MM-DD format.

    Purpose:
        Ensures consistent date handling for log file discovery and filtering.
        Accepts multiple input formats and fills missing year with 2026.

    Parameters:
        date_str: Optional input date. Can be None or empty. Accepted formats:
            - YYYY-MM-DD (returned unchanged)
            - DD/MM or DD-MM (with optional /YYYY or -YYYY); year defaults to 2026
            - MM-DD or MM/DD (US style); interpreted as month-day, year 2026

    Returns:
        A string in YYYY-MM-DD format, or the original string if it does not match
        any known pattern. Returns None if date_str is None or blank after strip.

    Behavior:
        - Leading/trailing whitespace is stripped.
        - Day and month are zero-padded to two digits in the output.
        - No validation of day/month ranges (e.g. 31/02 is still normalized).
    """
    if not date_str or not date_str.strip():
        return None
    s = date_str.strip()
    # Already YYYY-MM-DD
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        return s
    # DD/MM or DD-MM
    m = re.match(r"^(\d{1,2})[/\-](\d{1,2})(?:[/\-](\d{4}))?$", s)
    if m:
        d, mon, y = m.group(1), m.group(2), m.group(3)
        year = y or "2026"
        return f"{year}-{int(mon):02d}-{int(d):02d}"
    # MM-DD (US style)
    m = re.match(r"^(\d{1,2})[/\-](\d{1,2})$", s)
    if m:
        mon, d = m.group(1), m.group(2)
        return f"2026-{int(mon):02d}-{int(d):02d}"
    return s


def _rg_executable() -> Optional[str]:
    """
    Locate the ripgrep (rg) executable path for fast log search.

    Purpose:
        Enables use of rg when available; search falls back to Python grep otherwise.
        Checks environment and common install locations so users do not need rg on PATH.

    Parameters:
        None.

    Returns:
        The absolute path to the rg executable as a string, or None if rg cannot be found.

    Behavior:
        - First checks RG_PATH env var: if it points to a file, uses it; if it points to
          a directory, looks for rg.exe inside it.
        - Then uses shutil.which("rg") to find rg in the system PATH.
        - On Windows (os.name == "nt"), additionally checks: ProgramFiles/ripgrep,
          ProgramFiles(x86)/ripgrep, LOCALAPPDATA/Programs/ripgrep, USERPROFILE/scoop/shims,
          USERPROFILE/.cargo/bin. Logs when rg is found in one of these locations.
    """
    exe = os.environ.get("RG_PATH", "").strip()
    if exe:
        exe_path = Path(exe)
        if exe_path.is_file():
            return str(exe_path.resolve())
        if (exe_path / "rg.exe").is_file():
            return str((exe_path / "rg.exe").resolve())
    found = shutil.which("rg")
    if found:
        return found
    # Windows: common install locations
    if os.name == "nt":
        for candidate in [
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ripgrep" / "rg.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "ripgrep" / "rg.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "ripgrep" / "rg.exe",
            Path(os.environ.get("USERPROFILE", "")) / "scoop" / "shims" / "rg.exe",
            Path(os.environ.get("USERPROFILE", "")) / ".cargo" / "bin" / "rg.exe",
        ]:
            if candidate and candidate.is_file():
                log.info("Found rg at: %s", candidate)
                return str(candidate)
    return None

# ---------------------------------------------------------------------------
# Constants and compiled regex patterns (see NOTES: re.compile, os.environ, Path)
# ---------------------------------------------------------------------------

# Default log root directory (e.g. Log-CG). Resolved against cwd if relative.
# Overridable via environment variable LOG_ROOT.
LOG_ROOT = Path(os.environ.get("LOG_ROOT", "Log-CG")).resolve()

# Front-end servers: rejections and first-hop queue; search both for FES-related logs.
FES_SERVERS = ["FES01", "FES02"]
# Backend servers where QUEUE from <sender> and relay lines may appear.
VIP_SERVERS = ["VIP01", "VIP02"]
GP_SERVERS = ["GP01", "GP02"]
ML_SERVERS = ["ML01", "ML02"]
ALL_QUEUE_SERVERS = FES_SERVERS + VIP_SERVERS + GP_SERVERS + ML_SERVERS

# Log file naming (same in FES01 and FES02):
#   - YYYY-MM-DD.log           = Either a full-day log OR a log that stops when the first same-day
#                                 YYYY-MM-DD_HH-MM.log starts. It is a full-day log only when there
#                                 is no log file with format YYYY-MM-DD_HH-MM for that same day.
#   - YYYY-MM-DD_HH-MM.log     = time-slice log (e.g. 2026-01-29_10-52.log)
# For a given date we include ALL matching files (both patterns) in BOTH folders.

# Time at start of line: HH:MM:SS.mmm → groups: hour, minute, second, millisecond
TIME_RE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\.(\d{3})")
# Queue ID inside brackets: e.g. [1846565681] → group 1 = digits
QUEUE_ID_RE = re.compile(r"\[(\d+)\]")
# QUEUE([id]) from <sender> → groups: queue id, sender address
QUEUE_FROM_RE = re.compile(r"QUEUE\(\[(\d+)\]\) from <([^>]+)>")
# SMTPI-... (...) [queue_id] received → group 1 = queue id
SMTPI_RECEIVED_RE = re.compile(r"SMTPI-[^\s]+\([^)]+\) \[(\d+)\] received")
# DEQUEUER [queue_id] ... : rest of line → groups: queue id, remainder
DEQUEUER_RE = re.compile(r"DEQUEUER \[(\d+)\].*?:(.*)$")
# SMTP-... [queue_id] sent ... -> [ip]:port or -> dotted IP → groups: queue id, IP or None, dotted IP or None
SMTP_SENT_RE = re.compile(r"SMTP-[^\s]+\([^)]*\) \[(\d+)\] sent \[[^\]]+\]:\d+ -> (?:\[([^\]]+)\]|(\d+\.\d+\.\d+\.\d+)):\d+")
# Front-end rejection lines: timestamp, "1", SMTPI/Return-Path/Recipient, "rejected:", reason
REJECT_SMTPI_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{3}\s+1\s+SMTPI[^\n]*?(?:Return-Path\s+'([^']*)'|Recipient\s+([^\s]+))\s+rejected:\s*(.+)", re.MULTILINE)
REJECT_LINE_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{3}\s+1\s+(?:SMTPI[^:]+:\s*)?(?:Return-Path[^:]+:\s*)?(?:Recipient\s+[^\s]+\s+)?rejected:\s*(.+)$")
# Internal relay IPs: relay to these means we must search VIP/GP/ML for final delivery line
RELAY_VIP = "10.46.96.20"
RELAY_GP = "10.46.96.21"
RELAY_ML = "10.46.96.22"

# FES: SMTP sent line with got:250 and optional "N message accepted" -> delivery_id; queue id in []; relay IP in -> [IP]:port
SMTP_SENT_GOT250_RE = re.compile(
    r"^\d{2}:\d{2}:\d{2}\.\d{3}\s+.*?\s+SMTP-[^\s]+\([^)]*\)\s+\[(\d+)\]\s+sent\s+\[[^\]]+\]:\d+\s+->\s+\[?(\d+\.\d+\.\d+\.\d+)\]?:\d+.*?got:250\s+(\d+)\s+message\s+accepted",
    re.IGNORECASE,
)
# Fallback: SMTP sent with -> [IP]:port (relay IP) and got:250 (any format)
SMTP_SENT_RELAY_RE = re.compile(
    r"^\d{2}:\d{2}:\d{2}\.\d{3}\s+.*?\s+SMTP-[^\s]+\([^)]*\)\s+\[(\d+)\]\s+sent\s+.*?->\s+\[?(\d+\.\d+\.\d+\.\d+)\]?:\d+",
)
# DEQUEUER [qid] ... relayed: relayed via <IP or host>
DEQUEUER_RELAY_RE = re.compile(r"DEQUEUER\s+\[(\d+)\].*?relayed:\s*relayed via\s+(\S+)")
# DEQUEUER [qid] ... delivered: (local delivery, no need to check mapped servers)
DEQUEUER_LOCAL_DELIVERED_RE = re.compile(r"DEQUEUER\s+\[(\d+)\].*?delivered:")
# QUEUE([id]) from <sender>
QUEUE_FROM_RE_SENDER = re.compile(r"QUEUE\(\[(\d+)\]\) from <([^>]+)>")
# Delivery ID from "got:250 N message accepted" (anywhere in line)
GOT250_DELIVERY_ID_RE = re.compile(r"got:250\s+(\d+)\s+message\s+accepted", re.IGNORECASE)
# Success confirmation in downstream: only these matter
SUCCESS_RELAYED_GMAIL = "relayed via"
SUCCESS_GOT250_OK = "got:250 2.0.0 OK"

# Max matching lines for downstream delivery_id search (avoid truncation with many recipients)
DOWNSTREAM_SEARCH_MAX_COUNT = 100_000
# Batch size for downstream search; smaller batches avoid truncation when many delivery_ids
DOWNSTREAM_SEARCH_BATCH_SIZE = 400


def _line_minutes(line: str) -> Optional[int]:
    """Minutes since midnight from line start HH:MM:SS.mmm, or None."""
    ts = _parse_time_from_line(line)
    return int(ts // 60) if ts is not None else None


def _binary_search_start_offset(filepath: Path, start_min: int) -> int:
    """
    Binary search to find the byte offset of the first line with timestamp >= start_min.
    O(log n) seeks. Returns 0 if file empty or no such line.
    """
    try:
        size = filepath.stat().st_size
    except OSError:
        return 0
    if size == 0:
        return 0
    lo, hi = 0, size
    first_valid_offset = size
    max_iter = 80
    while lo < hi and max_iter > 0:
        max_iter -= 1
        mid = (lo + hi) // 2
        try:
            with open(filepath, "rb") as f:
                f.seek(mid)
                if mid > 0:
                    f.readline()
                pos = f.tell()
                raw = f.readline()
        except OSError:
            return 0
        if not raw:
            hi = mid
            continue
        try:
            line = raw.decode("utf-8", errors="ignore").rstrip("\n\r")
        except Exception:
            hi = mid
            continue
        mins = _line_minutes(line)
        if mins is None:
            hi = mid
            continue
        if mins < start_min:
            lo = pos + len(raw)
        else:
            first_valid_offset = min(first_valid_offset, pos)
            hi = mid
    return first_valid_offset if first_valid_offset <= size else 0


def _stream_lines_time_bounded(
    filepath: Path, start_min: int, end_min: int
) -> list[tuple[str, int]]:
    """
    Stream lines from file only within [start_min, end_min] (minutes since midnight).
    Uses binary search to find start offset, then reads sequentially. No full-file load.
    Returns list of (line_text, line_number) for lines in range.
    """
    start_off = _binary_search_start_offset(filepath, start_min)
    result = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(start_off)
            for num, line in enumerate(f, 1):
                line = line.rstrip("\n\r")
                mins = _line_minutes(line)
                if mins is not None and mins > end_min:
                    break
                if mins is not None and start_min <= mins <= end_min:
                    result.append((line, num))
    except OSError:
        pass
    return result


def _relay_ip_to_folders(relay_ip: str) -> list[str]:
    """Map relay IP last octet to server folders. .20->VIP, .21->GP, .22->ML."""
    if not relay_ip:
        return []
    if relay_ip.endswith(".20"):
        return list(VIP_SERVERS)
    if relay_ip.endswith(".21"):
        return list(GP_SERVERS)
    if relay_ip.endswith(".22"):
        return list(ML_SERVERS)
    return []


def _extract_rejection_message_only(line: str) -> Optional[str]:
    """
    Extract a concise rejection/failure message from a downstream (VIP/GP/ML) log line.

    Examples we want to catch:
        DEQUEUER [...] SMTP(gmail.com)... failed: message text rejected by gmail-smtp-in.l.google.com: ...
        DEQUEUER [...] SMTP(...)... rejected by <host>: <reason>

    Heuristics:
        - If "failed:" is present, take the text after "failed:" (stripped).
        - Otherwise, if "rejected by" is present, return text starting at "rejected by".
        - Returns None when no clear rejection indicator is found.
    """
    if not line:
        return None

    lower = line.lower()
    failed_idx = lower.find("failed:")
    if failed_idx != -1:
        # Keep everything after "failed:" as the message (original casing).
        return line[failed_idx + len("failed:"):].strip()

    rej_idx = lower.find("rejected by")
    if rej_idx != -1:
        return line[rej_idx:].strip()

    return None


def _extract_success_message_only(line: str) -> Optional[str]:
    """
    Extract only the meaningful success confirmation: either
    'relayed via gmail-smtp-in.l.google.com' or 'got:250 2.0.0 OK'. Returns None if neither.
    """
    if not line:
        return None

    # Most common pattern in VIP/GP/ML:
    #   DEQUEUER [107233712] SMTP(hotmail.fr)iheb... relayed: relayed via eur.olc.protection.outlook.com
    if "relayed via" in line:
        m = re.search(r"relayed:\s*relayed via\s+([^\s,;]+)", line)
        if not m:
            # Fallback: any "relayed via <host>" pattern
            m = re.search(r"relayed via\s+([^\s,;]+)", line)
        host = m.group(1).strip() if m else ""
        return f"relayed via {host}" if host else "relayed via"

    # Generic SMTP success line used by some backends
    if "got:250" in line and "2.0.0" in line and "OK" in line:
        return "got:250 2.0.0 OK"

    return None


def _search_smtp_sent_for_delivery_id(merged: list[tuple[str, Path, str]], idx: int, qid: str, lookahead: int = 500) -> Optional[str]:
    """
    Search forward in merged stream for an SMTP_SENT line with the given queue_id that contains delivery_id.
    Used when DEQUEUER is seen before SMTP_SENT so we can still get delivery_id for downstream search.
    """
    for j in range(idx + 1, min(idx + 1 + lookahead, len(merged))):
        line, _, _ = merged[j]
        if f"[{qid}]" not in line:
            continue
        m = SMTP_SENT_RELAY_RE.search(line)
        if m and m.group(1) == qid:
            dm = GOT250_DELIVERY_ID_RE.search(line)
            if dm:
                return dm.group(1)
            return None
        if f"QUEUE([{qid}])" in line and "deleted" in line:
            break
    return None


def _search_fes_time_bounded(
    log_root: Path,
    date_str: str,
    time_range: tuple[int, int],
    sender: Optional[str],
    recipient: Optional[str],
) -> list[dict]:
    """
    Time-bounded FES search: only open files overlapping the window, binary-seek to start,
    scan only lines in [start_min, end_min]. Extract: timestamp, sender, receiver, delivery_id,
    relay_ip, fes_log_line (SMTP sent with got:250), queue_id.
    DEQUEUER is used only to get relay IP and recipient; the canonical FES line is the SMTP sent line.
    Uses a merged stream across all files so recent_queue persists (fixes cross-file correlation).
    When DEQUEUER is seen before SMTP_SENT, traces forward for delivery_id.
    """
    start_min, end_min = time_range
    files = _get_ordered_files_for_merge(log_root, date_str, time_range=time_range)
    
    # If time range is near midnight (end_min >= 1430 = 23:50), also check next day's early morning files
    # to catch DEQUEUER entries that complete traces started late at night
    next_day_files = []
    if end_min >= 1430:  # 23:50 or later
        next_date = _date_next(date_str)
        # Search next day from 00:00 to 00:15 (15 minutes after midnight) to catch cross-midnight deliveries
        next_day_time_range = (0, 15)
        next_day_files = _get_ordered_files_for_merge(log_root, next_date, time_range=next_day_time_range)
    
    if not files and not next_day_files:
        return []
    sender_lower = (sender or "").strip().lower()
    recipient_lower = (recipient or "").strip().lower()

    merged: list[tuple[str, Path, str]] = []  # (line, filepath, date_str)
    for filepath in files:
        lines_with_nums = _stream_lines_time_bounded(filepath, start_min, end_min)
        for line, _ in lines_with_nums:
            merged.append((line, filepath, date_str))
    
    # Add next day's early morning lines
    next_date = _date_next(date_str) if end_min >= 1430 else date_str
    for filepath in next_day_files:
        lines_with_nums = _stream_lines_time_bounded(filepath, 0, 15)  # 00:00 to 00:15
        for line, _ in lines_with_nums:
            merged.append((line, filepath, next_date))

    results = []
    seen = set()
    recent_queue: dict[str, dict] = {}

    for idx, (line, filepath, line_date) in enumerate(merged):
        server = _server_from_filepath(str(filepath))
        m = QUEUE_FROM_RE.search(line)
        if m:
            qid, from_sender = m.group(1), m.group(2)
            if sender_lower and sender_lower not in from_sender.lower():
                continue
            recent_queue[qid] = {"sender": from_sender, "qid": qid}
            continue
        m = SMTP_SENT_RELAY_RE.search(line)
        if m:
            qid, relay_ip = m.group(1), m.group(2)
            delivery_id = None
            dm = GOT250_DELIVERY_ID_RE.search(line)
            if dm:
                delivery_id = dm.group(1)
            if qid not in recent_queue:
                continue
            rec = recent_queue[qid]
            rec["relay_ip"] = relay_ip
            rec["delivery_id"] = delivery_id
            rec["fes_log_line"] = line
            rec["smpt_line_ts"] = _parse_time_from_line(line)
            continue
        m_local = DEQUEUER_LOCAL_DELIVERED_RE.search(line)
        if m_local:
            qid = m_local.group(1)
            if qid in recent_queue:
                rec = recent_queue[qid]
                rec_recipient = _extract_recipient_from_dequeuer(line)
                if recipient_lower and rec_recipient and recipient_lower not in rec_recipient.lower():
                    pass
                else:
                    rec["receiver"] = rec_recipient or rec.get("receiver", "")
                    rec["dequeuer_line"] = line
                    if not rec.get("fes_log_line"):
                        rec["fes_log_line"] = line
                        rec["smpt_line_ts"] = _parse_time_from_line(line)
                    key = (rec["qid"], rec.get("sender", ""), rec.get("receiver", ""), line)
                    if key not in seen:
                        seen.add(key)
                        ts = rec.get("smpt_line_ts")
                        time_part = f"{int(ts)//3600:02d}:{(int(ts)%3600)//60:02d}:{int(ts)%60:02d}" if ts is not None else ""
                        results.append({
                            "timestamp": f"{line_date}T{time_part}" if time_part else line_date,
                            "sender": rec.get("sender", ""),
                            "receiver": rec.get("receiver", ""),
                            "delivery_id": None,
                            "queue_id": rec["qid"],
                            "relay_ip": None,
                            "fes_log_line": rec.get("fes_log_line", ""),
                            "dequeuer_line": line,
                            "dequeuer_line_mapped": "",
                            "smtp_sent_line": rec.get("smtp_sent_line", ""),
                            "fes_server": server,
                            "fes_file": filepath.name,
                            "local_delivery_success": True,
                        })
            continue
        m = DEQUEUER_RELAY_RE.search(line)
        if m:
            qid, relay_addr = m.group(1), m.group(2)
            rec_recipient = _extract_recipient_from_dequeuer(line)
            if not rec_recipient and "SMTP(" in line:
                rec_recipient = re.search(r"SMTP\([^)]*\)([^\s]+)\s+relayed", line)
                rec_recipient = rec_recipient.group(1).strip() if rec_recipient else ""
            if qid not in recent_queue:
                continue
            rec = recent_queue[qid]
            if recipient_lower and rec_recipient and recipient_lower not in rec_recipient.lower():
                continue
            rec["receiver"] = rec_recipient
            rec["dequeuer_line"] = line
            if not rec.get("relay_ip"):
                rec["relay_ip"] = relay_addr if re.match(r"\d+\.\d+\.\d+\.\d+", relay_addr) else None
            if not rec.get("fes_log_line"):
                rec["fes_log_line"] = line
                rec["smpt_line_ts"] = _parse_time_from_line(line)
            if relay_addr and re.match(r"10\.46\.96\.(20|21|22)$", relay_addr):
                rec["dequeuer_line_mapped"] = line
            if rec.get("fes_log_line") and rec.get("relay_ip"):
                delivery_id = rec.get("delivery_id")
                if delivery_id is None:
                    delivery_id = _search_smtp_sent_for_delivery_id(merged, idx, qid)
                    if delivery_id is not None:
                        rec["delivery_id"] = delivery_id
                key = (rec["qid"], rec.get("sender", ""), rec.get("receiver", ""), rec.get("fes_log_line"))
                if key not in seen:
                    seen.add(key)
                    ts = rec.get("smpt_line_ts")
                    time_part = f"{int(ts)//3600:02d}:{(int(ts)%3600)//60:02d}:{int(ts)%60:02d}" if ts is not None else ""
                    results.append({
                        "timestamp": f"{line_date}T{time_part}" if time_part else line_date,
                        "sender": rec.get("sender", ""),
                        "receiver": rec.get("receiver", ""),
                        "delivery_id": rec.get("delivery_id"),
                        "queue_id": rec["qid"],
                        "relay_ip": rec.get("relay_ip"),
                        "fes_log_line": rec.get("fes_log_line", ""),
                        "dequeuer_line": rec.get("dequeuer_line", ""),
                        "dequeuer_line_mapped": rec.get("dequeuer_line_mapped", ""),
                        "smtp_sent_line": rec.get("smtp_sent_line", ""),
                        "fes_server": server,
                        "fes_file": filepath.name,
                    })
    return results


def _group_fes_hits_by_server(fes_hits: list[dict]) -> list[tuple[str, list[str], set[str]]]:
    """
    Group FES hits by target server group (VIP, GP, ML). No per-ID searching.
    Returns list of (group_name, folder_list, set of queue_ids) for each non-empty group.
    """
    vip_ids: set[str] = set()
    gp_ids: set[str] = set()
    ml_ids: set[str] = set()
    for hit in fes_hits:
        relay_ip = hit.get("relay_ip") or ""
        qid = hit.get("queue_id") or ""
        if not qid:
            continue
        if relay_ip.endswith(".20"):
            vip_ids.add(qid)
        elif relay_ip.endswith(".21"):
            gp_ids.add(qid)
        elif relay_ip.endswith(".22"):
            ml_ids.add(qid)
    out: list[tuple[str, list[str], set[str]]] = []
    if vip_ids:
        out.append(("VIP", list(VIP_SERVERS), vip_ids))
    if gp_ids:
        out.append(("GP", list(GP_SERVERS), gp_ids))
    if ml_ids:
        out.append(("ML", list(ML_SERVERS), ml_ids))
    return out


def _group_fes_hits_by_server_with_delivery_id(
    fes_hits: list[dict],
) -> list[tuple[str, list[str], set[str], dict[str, str]]]:
    """
    Group FES hits by target server (VIP/GP/ML). Returns for each group:
    (group_name, folder_list, set of delivery_ids to search, map delivery_id -> queue_id).
    Only includes hits that have a non-empty delivery_id for downstream search.
    """
    vip: list[tuple[str, str]] = []  # (queue_id, delivery_id)
    gp: list[tuple[str, str]] = []
    ml: list[tuple[str, str]] = []
    for hit in fes_hits:
        relay_ip = hit.get("relay_ip") or ""
        qid = hit.get("queue_id") or ""
        did = (hit.get("delivery_id") or "").strip()
        if not qid or not did:
            continue
        if relay_ip.endswith(".20"):
            vip.append((qid, did))
        elif relay_ip.endswith(".21"):
            gp.append((qid, did))
        elif relay_ip.endswith(".22"):
            ml.append((qid, did))
    out: list[tuple[str, list[str], set[str], dict[str, str]]] = []
    if vip:
        did_set = {d for _, d in vip}
        did_to_qid = {d: q for q, d in vip}
        out.append(("VIP", list(VIP_SERVERS), did_set, did_to_qid))
    if gp:
        did_set = {d for _, d in gp}
        did_to_qid = {d: q for q, d in gp}
        out.append(("GP", list(GP_SERVERS), did_set, did_to_qid))
    if ml:
        did_set = {d for _, d in ml}
        did_to_qid = {d: q for q, d in ml}
        out.append(("ML", list(ML_SERVERS), did_set, did_to_qid))
    return out


def _date_prev(date_str: str) -> str:
    """Return previous day in YYYY-MM-DD. Used for downstream cross-midnight search."""
    try:
        from datetime import datetime, timedelta
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        prev = (dt - timedelta(days=1)).strftime("%Y-%m-%d")
        return prev
    except (ValueError, TypeError):
        return date_str


def _date_next(date_str: str) -> str:
    """Return next day in YYYY-MM-DD. Used for FES cross-midnight search."""
    try:
        from datetime import datetime, timedelta
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        next_day = (dt + timedelta(days=1)).strftime("%Y-%m-%d")
        return next_day
    except (ValueError, TypeError):
        return date_str


def _search_downstream_by_delivery_id(
    log_root: Path,
    date_str: str,
    servers: list[str],
    delivery_ids_needed: set[str],
    time_range: Optional[tuple[int, int]] = None,
) -> dict[str, tuple[str, str, list[str]]]:
    """
    Search downstream (VIP/GP/ML) logs by delivery ID.
    When time_range is provided: only files overlapping the window and only lines within
    [start_min, end_min] are scanned (binary search for start offset, then sequential read).
    When time_range is None: all files for date + previous day, rg or full-file scan.
    Returns map delivery_id -> (mapped_folder, success_message, success_log_lines).
    """
    result: dict[str, tuple[str, str, list[str]]] = {}
    if not delivery_ids_needed:
        return result

    if time_range is not None:
        start_min, end_min = time_range
        files = _get_ordered_files_for_servers(log_root, servers, date_str, time_range)
        prev_files = _get_ordered_files_for_servers(log_root, servers, _date_prev(date_str), time_range)
        seen_paths = {p.resolve() for p in files}
        for p in prev_files:
            if p.resolve() not in seen_paths:
                files.append(p)
                seen_paths.add(p.resolve())
        path_list = [p for p in files if p.exists()]
        remaining = set(delivery_ids_needed) - result.keys()
        for filepath in path_list:
            if not remaining:
                break
            server = _server_from_filepath(str(filepath))
            folder_str = f"{server}/{filepath.name}" if server else filepath.name
            for line, _ in _stream_lines_time_bounded(filepath, start_min, end_min):
                msg = _extract_success_message_only(line)
                if msg:
                    for did in list(remaining):
                        if f"[{did}]" in line:
                            if did not in result:
                                result[did] = (folder_str, msg, [])
                            result[did][2].append(line)
                            remaining.discard(did)
                            break
        return result

    files = _get_log_files_for_servers(log_root, servers, date_str)
    prev_files = _get_log_files_for_servers(log_root, servers, _date_prev(date_str))
    seen_paths = {p.resolve() for p in files}
    for p in prev_files:
        if p.resolve() not in seen_paths:
            files.append(p)
            seen_paths.add(p.resolve())
    if not files:
        return result
    path_list = [p for p in files if p.exists()]
    if not path_list:
        return result

    ids_list = list(delivery_ids_needed)
    batch_size = DOWNSTREAM_SEARCH_BATCH_SIZE
    for start in range(0, len(ids_list), batch_size):
        batch_ids = set(ids_list[start : start + batch_size])
        remaining = batch_ids - result.keys()
        if not remaining:
            continue
        escaped = [re.escape(d) for d in remaining]
        pattern = "|".join(r"\[" + d + r"\]" for d in escaped)
        hits = _run_rg(pattern, path_list, log_root, max_count=DOWNSTREAM_SEARCH_MAX_COUNT)
        for filepath_str, line_no, line_text in hits:
            if not remaining:
                break
            msg = _extract_success_message_only(line_text)
            if not msg:
                continue
            for did in list(remaining):
                if f"[{did}]" in line_text:
                    if did not in result:
                        server = _server_from_filepath(filepath_str)
                        folder_str = f"{server}/{Path(filepath_str).name}" if server else Path(filepath_str).name
                        result[did] = (folder_str, msg, [])
                    result[did][2].append(line_text)
                    remaining.discard(did)
                    break
    return result


def _search_downstream_rejections_by_delivery_id(
    log_root: Path,
    date_str: str,
    servers: list[str],
    delivery_ids_needed: set[str],
) -> dict[str, tuple[str, str, list[str]]]:
    """
    Search downstream (VIP/GP/ML) logs by delivery ID for rejection indicators instead of success.

    Behavior:
        - Scans log files for the given date plus previous day (to handle cross-midnight cases).
        - Uses rg (or Python grep) to find lines containing any of the delivery IDs (as [DID]).
        - For each matching line, attempts to extract a rejection message via _extract_rejection_message_only.
        - Returns map delivery_id -> (mapped_folder, rejection_message, rejection_log_lines).

    This is used when no delivery success was found, so each FES log can still show either
    a success indicator or a rejection indicator from the mapped servers.
    """
    result: dict[str, tuple[str, str, list[str]]] = {}
    if not delivery_ids_needed:
        return result

    files = _get_log_files_for_servers(log_root, servers, date_str)
    prev_files = _get_log_files_for_servers(log_root, servers, _date_prev(date_str))
    seen_paths = {p.resolve() for p in files}
    for p in prev_files:
        if p.resolve() not in seen_paths:
            files.append(p)
            seen_paths.add(p.resolve())
    if not files:
        return result
    path_list = [p for p in files if p.exists()]
    if not path_list:
        return result

    ids_list = list(delivery_ids_needed)
    batch_size = DOWNSTREAM_SEARCH_BATCH_SIZE
    for start in range(0, len(ids_list), batch_size):
        batch_ids = set(ids_list[start : start + batch_size])
        remaining = batch_ids - result.keys()
        if not remaining:
            continue
        escaped = [re.escape(d) for d in remaining]
        pattern = "|".join(r"\[" + d + r"\]" for d in escaped)
        hits = _run_rg(pattern, path_list, log_root, max_count=DOWNSTREAM_SEARCH_MAX_COUNT)
        for filepath_str, line_no, line_text in hits:
            if not remaining:
                break
            msg = _extract_rejection_message_only(line_text)
            if not msg:
                continue
            for did in list(remaining):
                if f"[{did}]" in line_text:
                    if did not in result:
                        server = _server_from_filepath(filepath_str)
                        folder_str = f"{server}/{Path(filepath_str).name}" if server else Path(filepath_str).name
                        result[did] = (folder_str, msg, [])
                    result[did][2].append(line_text)
                    remaining.discard(did)
                    break
    return result

def _single_pass_search_group(
    log_root: Path,
    date_str: str,
    time_range: tuple[int, int],
    servers: list[str],
    queue_ids_needed: set[str],
) -> dict[str, tuple[str, str, list[str]]]:
    """
    Single-pass search for a server group: list files once, scan each file at most once.
    Uses O(1) set membership for delivery/queue IDs. Stops scanning a file when all IDs
    in queue_ids_needed are found (early exit). Returns map queue_id -> (mapped_folder, success_message, success_log_lines).
    success_log_lines are the full raw log lines (e.g. SMTP sent got:250, DEQUEUER relayed via).
    (Legacy: used when delivery_id is missing; downstream is searched by queue_id in time range.)
    """
    result: dict[str, tuple[str, str, list[str]]] = {}
    if not queue_ids_needed:
        return result
    start_min, end_min = time_range
    files = _get_ordered_files_for_servers(log_root, servers, date_str, time_range)
    if not files:
        return result
    remaining = set(queue_ids_needed)
    for filepath in files:
        if not remaining:
            break
        lines_with_nums = _stream_lines_time_bounded(filepath, start_min, end_min)
        server = _server_from_filepath(str(filepath))
        folder_str = f"{server}/{filepath.name}" if server else filepath.name
        found_this_file: set[str] = set()
        for line, _ in lines_with_nums:
            if not remaining:
                break
            msg = _extract_success_message_only(line)
            if not msg:
                continue
            for qid in QUEUE_ID_RE.findall(line):
                if qid in remaining:
                    if qid not in result:
                        result[qid] = (folder_str, msg, [])
                    result[qid][2].append(line)
                    found_this_file.add(qid)
                    if not remaining:
                        break
        remaining -= found_this_file
    return result


def _run_rg(pattern: str, paths: list[Path], log_root: Path, max_count: int = 5000) -> list[tuple[str, int, str]]:
    """
    Run ripgrep (rg) to search for a regex pattern in the given file paths; fall back to Python grep if rg is unavailable.

    Purpose:
        Provides fast line-oriented search across large log files. Uses rg when found via _rg_executable();
        otherwise calls _python_grep so the pipeline still works without rg.

    Parameters:
        pattern: Regex pattern string passed to rg -e (or compiled in Python fallback). No automatic escaping.
        paths: List of Path objects to search; only existing paths are used; empty list returns [].
        log_root: Root path (used for logging context; not used to resolve paths here).
        max_count: Maximum number of matching lines to return (default 5000). rg output and Python fallback both respect this.

    Returns:
        List of 3-tuples: (filepath, line_number, line_text). filepath is string; line_text is the full line without trailing newline.
        At most max_count entries. Order is rg’s output order or file iteration order in Python fallback.

    Behavior:
        - Filters paths to those that exist; if none exist, returns [].
        - Invokes rg with --line-number, --no-heading, -e <pattern>, timeout 120s, capture_output=True, text=True.
        - Parses "path:line_no:line_text" from stdout (split on ":", 2); skips lines that do not parse or have invalid line numbers.
        - On rg failure (FileNotFoundError, TimeoutExpired, or other exception), falls back to _python_grep and logs a warning.
        - If rg is not found, logs warning and uses _python_grep without running rg.
    """
    if not paths:
        return []
    path_list = [p for p in paths if p.exists()]
    if not path_list:
        return []
    path_strs = [str(p) for p in path_list]
    rg_exe = _rg_executable()
    if rg_exe:
        log.info("Step: Running ripgrep (rg) with pattern %r on %d file(s)", pattern[:60] + "..." if len(pattern) > 60 else pattern, len(path_strs))
        try:
            result = subprocess.run(
                [rg_exe, "--line-number", "--no-heading", "-e", pattern, *path_strs],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=None,
            )
            out = (result.stdout or "").strip()
            hit_count = len(out.splitlines()) if out else 0
            log.info("  rg returned %d matching line(s)", hit_count)
            if result.stderr:
                log.debug("  rg stderr: %s", result.stderr[:200])
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            log.warning("  rg failed: %s; falling back to Python grep", e)
            out = ""
    else:
        log.warning(
            "Step: ripgrep (rg) not found. Using slow Python fallback. "
            "Install rg and add to PATH, or set RG_PATH: https://github.com/BurntSushi/ripgrep#installation"
        )
        out = ""
    if not out:
        out_list = _python_grep(pattern, path_list, max_count)
        log.info("  Python grep returned %d matching line(s)", len(out_list))
        return out_list
    lines = out.split("\n")[:max_count]
    parsed = []
    # rg outputs path:line_no:line_text; line_text can contain ":" (e.g. timestamps).
    # Line number is the last ":\d+:" with 4+ digits (log line numbers; timestamps use 1-2 digits).
    line_no_pattern = re.compile(r":(\d{4,}):")
    for line in lines:
        match = list(line_no_pattern.finditer(line))
        if not match:
            continue
        last = match[-1]
        line_no_str = last.group(1)
        path = line[: last.start()]
        line_text = line[last.end() :]
        try:
            num = int(line_no_str)
            parsed.append((path, num, line_text))
        except ValueError:
            pass
    return parsed


def _python_grep(pattern: str, paths: list[Path], max_count: int, max_lines_per_file: int = 50_000) -> list[tuple[str, int, str]]:
    """
    Search for a regex pattern in files using Python; return matching lines with location.

    Purpose:
        Fallback when ripgrep is not available. Reads files sequentially and applies regex search per line,
        with caps to avoid excessive memory and CPU on huge logs.

    Parameters:
        pattern: Regex pattern string. Compiled with re.IGNORECASE; if compilation fails, re.escape(pattern) is used.
        paths: List of Path objects to search; non-existent or unreadable files are skipped silently.
        max_count: Stop collecting after this many matches across all files.
        max_lines_per_file: Stop reading each file after this many lines (default 50_000) to bound work per file.

    Returns:
        List of 3-tuples: (filepath, line_number, line_text). filepath is str(path); line_text has trailing newline stripped.

    Behavior:
        - Files are processed in list order. Within each file, lines are read with open(..., encoding="utf-8", errors="ignore").
        - Matching uses pat.search(line) (anywhere in line). Line numbers are 1-based (enumerate(..., 1)).
        - Stops iterating a file after max_lines_per_file lines; stops entirely when result length reaches max_count.
        - On any exception per file (IO, decode), the file is skipped (continue).
    """
    import re
    try:
        pat = re.compile(pattern, re.IGNORECASE)
    except re.error:
        pat = re.compile(re.escape(pattern), re.IGNORECASE)
    result = []
    for path in paths:
        if len(result) >= max_count:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, 1):
                    if i > max_lines_per_file:
                        break
                    if pat.search(line):
                        result.append((str(path), i, line.rstrip("\n")))
                        if len(result) >= max_count:
                            break
        except Exception:
            continue
    return result


def _get_log_files_for_servers(log_root: Path, servers: list[str], date_str: Optional[str]) -> list[Path]:
    """
    List log files under log_root for the given server folders, optionally filtered by date.

    Purpose:
        Discovers all .log files under each server directory (e.g. FES01, FES02) for use in search or merge.
        Supports both YYYY-MM-DD.log (full-day or segment until first time-slice; see module comment above)
        and time-slice (YYYY-MM-DD_HH-MM.log) naming.

    Parameters:
        log_root: Root directory containing server subdirs (e.g. Log-CG). If not absolute, resolved against Path.cwd().
        servers: List of server folder names (e.g. ["FES01", "FES02"]). Only existing directories are scanned.
        date_str: Optional YYYY-MM-DD string. If provided, only files whose stem starts with this date are included;
                  if None, all .log files whose stem starts with a YYYY-MM-DD prefix are included.

    Returns:
        List of Path objects for matching log files. Order is per-server then sorted by filename; may include files from multiple servers.

    Behavior:
        - Skips non-directories and files that are not .log or whose name starts with ".".
        - Stem must start with a substring matching ^\\d{4}-\\d{2}-\\d{2}$ (either the full stem or the part before "_").
        - Logs the number of files found and up to 10 filenames (then "..." if more).
    """
    files = []
    root = log_root if log_root.is_absolute() else (Path.cwd() / log_root)
    log.info("Step: Listing log files in folders %s (date_filter=%s)", servers, date_str)
    for server in servers:
        dir_path = root / server
        if not dir_path.is_dir():
            log.debug("  Skip %s (not a directory)", dir_path)
            continue
        for f in sorted(dir_path.iterdir()):
            if f.suffix != ".log" or f.name.startswith("."):
                continue
            stem = f.stem
            base = stem.split("_")[0]
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", base):
                continue
            if date_str and base != date_str:
                continue
            files.append(f)
    log.info("  Found %d log file(s): %s", len(files), [f.name for f in files[:10]] + (["..."] if len(files) > 10 else []))
    return files


def _parse_time_to_minutes(t: Optional[str]) -> Optional[int]:
    """Parse H, HH, HH:MM or HH:MM:SS to minutes since midnight. Hour-only → minutes default to 00 (e.g. 9 → 09:00)."""
    if not t or not str(t).strip():
        return None
    parts = str(t).strip().split(":")
    try:
        h = int(parts[0])
        m = int(parts[1]) if (len(parts) >= 2 and parts[1].strip()) else 0
        s = int(parts[2]) if (len(parts) >= 3 and parts[2].strip()) else 0
        if 0 <= h <= 23 and 0 <= m <= 59 and 0 <= s <= 59:
            return h * 60 + m
    except (ValueError, IndexError):
        pass
    return None


def _line_in_time_range(line: str, time_range: Optional[tuple[int, int]]) -> bool:
    """True if line's HH:MM:SS timestamp is within time_range (minutes), or if time_range is None."""
    if not time_range:
        return True
    ts = _parse_time_from_line(line)
    if ts is None:
        return True
    mins = int(ts // 60)
    return time_range[0] <= mins <= time_range[1]


def _get_ordered_files_for_servers(
    log_root: Path, servers: list[str], date_str: str, time_range: Optional[tuple[int, int]] = None
) -> list[Path]:
    """
    Get log files for the given server list (e.g. VIP01,VIP02), date, and optional time range.
    Lists files once. When time_range is set, only includes time-slice files that overlap the window;
    when overlapping slices exist, excludes full-day file. Returns sorted list (chronological).
    """
    all_files = _get_log_files_for_servers(log_root, servers, date_str)
    if not all_files:
        return []

    full_day = [p for p in all_files if "_" not in p.stem]
    time_slices = [p for p in all_files if "_" in p.stem]

    if time_range:
        start_min, end_min = time_range
        filtered_slices = []
        for p in time_slices:
            try:
                h, m = p.stem.split("_")[1].split("-")
                slice_min = int(h) * 60 + int(m)
                slice_end = slice_min + 60
                if slice_end <= start_min or slice_min > end_min:
                    continue
                filtered_slices.append(p)
            except (ValueError, IndexError):
                pass
        if filtered_slices:
            time_slices = filtered_slices
            full_day = []

    def sort_key(p: Path) -> tuple[int, int]:
        stem = p.stem
        if "_" not in stem:
            return (0, 0)
        try:
            h, m = stem.split("_")[1].split("-")
            return (1, int(h) * 60 + int(m))
        except (ValueError, IndexError):
            return (2, 0)

    return sorted(full_day + time_slices, key=sort_key)


def _get_ordered_files_for_merge(
    log_root: Path, date_str: str, time_range: Optional[tuple[int, int]] = None
) -> list[Path]:
    """
    Get FES log files for date, ordered chronologically.
    When time_range (start_min, end_min) is set:
    - Time-slice files (YYYY-MM-DD_HH-MM.log): include only if slice overlaps [start, end].
    - Daily log (YYYY-MM-DD.log): covers midnight→first split; include if overlaps.
    - When overlapping time-slices exist, exclude daily for scalability.
    """
    return _get_ordered_files_for_servers(log_root, FES_SERVERS, date_str, time_range)


def _extract_recipient_from_dequeuer(line: str) -> str:
    """
    Extract the recipient address from a DEQUEUER log line.

    Purpose:
        DEQUEUER lines indicate delivery/relay; this function parses the recipient part for display and filtering
        (e.g. LOCAL(addr)recipient, SMTP(...)recipient, SYSTEM()<recipient>).

    Parameters:
        line: Full log line containing "DEQUEUER [id] ... LOCAL(...) or SMTP(...) or SYSTEM(...) <recipient> delivered|relayed|failed".

    Returns:
        The recipient string, with surrounding angle brackets removed if present. Empty string if no match.

    Behavior:
        - Uses regex to find the token after LOCAL(...)/SMTP(...)/SYSTEM(...) and before delivered|relayed|failed.
        - Strips whitespace and removes leading/trailing <> from that token.
    """
    m = re.search(
        r"DEQUEUER \[[\d]+\] (?:LOCAL\([^)]*\)|SMTP\([^)]*\)|SYSTEM\([^)]*\))([^\s]+) (?:delivered|relayed|failed)",
        line,
    )
    if m:
        rec = m.group(1).strip()
        return rec.strip("<>") if rec.startswith("<") else rec
    return ""


def _parse_time_from_line(line: str) -> Optional[float]:
    """
    Parse the timestamp at the start of a log line and return seconds since midnight.

    Purpose:
        Enables time-based ordering and display. Log lines start with HH:MM:SS.mmm (TIME_RE).

    Parameters:
        line: A single log line; leading whitespace is stripped before matching.

    Returns:
        Seconds since midnight as a float (hours*3600 + minutes*60 + seconds + milliseconds/1000), or None if the line does not start with a matching timestamp.
    """
    m = TIME_RE.match(line.strip())
    if not m:
        return None
    h, mi, s, ms = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
    return h * 3600 + mi * 60 + s + ms / 1000.0


def _date_from_filepath(filepath: str) -> str:
    """
    Extract the date portion (YYYY-MM-DD) from a log filename.

    Purpose:
        Log files are named by date (and optionally time slice); this provides the date for result metadata.

    Parameters:
        filepath: Path or filename string (e.g. "Log-CG/FES01/2026-01-29.log" or "2026-01-29_10-52.log").

    Returns:
        The YYYY-MM-DD prefix from the file stem (part before first "_", or full stem if no "_"), or empty string if the stem does not match ^\\d{4}-\\d{2}-\\d{2}$.
    """
    base = Path(filepath).stem.split("_")[0]
    if re.match(r"^\d{4}-\d{2}-\d{2}$", base):
        return base
    return ""


def _server_from_filepath(filepath: str) -> str:
    """
    Extract the server name (e.g. FES01, VIP02) from a log file path.

    Purpose:
        Paths contain a server folder name; this identifies which server produced the log line for display and filtering.

    Parameters:
        filepath: Full path or path segments string (e.g. "C:/Log-CG/FES01/2026-01-29.log").

    Returns:
        The first path component that is in FES_SERVERS + VIP_SERVERS + GP_SERVERS + ML_SERVERS, or empty string if none.
    """
    parts = Path(filepath).parts
    for p in parts:
        if p in FES_SERVERS + VIP_SERVERS + GP_SERVERS + ML_SERVERS:
            return p
    return ""


def _relay_to_server(relay_ip: str) -> Optional[str]:
    """
    Map an internal relay IP suffix to the next-hop server name.

    Purpose:
        SMTP relay lines contain destination IPs; internal relays use fixed suffixes that map to VIP01, GP01, ML01.
        Used to build server path for accepted mail flow (currently not used in main search results but available for extensions).

    Parameters:
        relay_ip: Dotted IP string (e.g. "10.46.96.20"). Only the last octet is considered.

    Returns:
        "VIP01" if relay_ip ends with ".20", "GP01" for ".21", "ML01" for ".22"; otherwise None (external relay).
    """
    if not relay_ip:
        return None
    if relay_ip.endswith(".20"):
        return "VIP01"
    if relay_ip.endswith(".21"):
        return "GP01"
    if relay_ip.endswith(".22"):
        return "ML01"
    return None


def _parse_rejection_line(line: str) -> Optional[dict]:
    """
    Parse a front-end rejection log line into structured fields.

    Purpose:
        Rejection lines have formats like "1 SMTPI-... Return-Path 'sender' rejected: reason" or
        "1 ... Recipient addr rejected: reason". This extracts sender (if present), recipient (if present), and reason.

    Parameters:
        line: A single log line that is expected to contain " 1 " and "rejected" (front-end rejection format).

    Returns:
        None if the line does not contain " 1 " and "rejected". Otherwise a dict with keys:
        - "sender": from Return-Path, or None
        - "recipient": from Recipient token, or None
        - "errorMessage": the text after "rejected:" (stripped)
    """
    # 1 SMTPI-635041([41.224.57.161]) Return-Path 'waf@monetique.com.tn' rejected: You must authenticate first
    # 1 SMTPI-635042([197.26.11.153]) Recipient webservice@interbrands.com.tn rejected: account is full (quota exceeded), rejecting
    if " 1 " not in line or "rejected" not in line:
        return None
    sender = None
    recipient = None
    if "Return-Path" in line:
        m = re.search(r"Return-Path\s+'([^']*)'\s+rejected:\s*(.+)", line)
        if m:
            sender = m.group(1).strip()
            reason = m.group(2).strip()
        else:
            reason = line.split("rejected:", 1)[-1].strip()
    elif "Recipient" in line:
        m = re.search(r"Recipient\s+(\S+)\s+rejected:\s*(.+)", line)
        if m:
            recipient = m.group(1).strip()
            reason = m.group(2).strip()
        else:
            reason = line.split("rejected:", 1)[-1].strip()
    else:
        reason = line.split("rejected:", 1)[-1].strip()
    return {"sender": sender, "recipient": recipient, "errorMessage": reason}


def _read_file_lines(filepath: Path, around_line: Optional[int] = None, context: int = 500) -> list[str]:
    """
    Read lines from a log file, optionally only around a specific line number.

    Purpose:
        Supports fetching full file content or a window around a hit for display (e.g. rejection or QUEUE line context).

    Parameters:
        filepath: Path to the file. If relative and not found in cwd, LOG_ROOT / filepath is tried.
        around_line: If provided (1-based line number), only lines [around_line - 1 - context, around_line + context) are returned.
        context: Number of lines before and after around_line to include (default 500).

    Returns:
        List of lines (including newlines). Empty list if file cannot be read or does not exist.

    Behavior:
        - Uses open(..., encoding="utf-8", errors="ignore"). readlines() so each element is a full line.
        - Clamps start to 0 and end to len(lines) when slicing around_line.
    """
    path = filepath if isinstance(filepath, Path) else Path(filepath)
    if not path.is_absolute() and not path.exists():
        path = LOG_ROOT / path
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return []
    if around_line is None:
        return lines
    start = max(0, around_line - 1 - context)
    end = min(len(lines), around_line + context)
    return lines[start:end]


def find_front_end_rejections(
    log_root: Path, sender: str, recipient: Optional[str], date_str: Optional[str],
    time_range: Optional[tuple[int, int]] = None,
) -> list[dict]:
    """
    Search FES01 and FES02 log files for front-end rejection lines (no queue ID) matching sender and/or recipient.

    Purpose:
        Front-end rejections occur before a queue ID is assigned. This function finds all such lines for the given
        date and search criteria and returns them as a list of result dicts compatible with the main search API.

    Parameters:
        log_root: Root directory containing FES01 and FES02 (Path or path-like). Converted to Path if not.
        sender: Sender address to search for (e.g. Return-Path). Can be empty if recipient is set.
        recipient: Optional recipient to search for; if set with no sender, only recipient is used in the pattern.
        date_str: Date filter in YYYY-MM-DD; only log files for this date are searched. None skips rejections (returns []).

    Returns:
        List of dicts, each with: id, sender, recipient, direction ("Sent"), date (ISO local), status ("Rejected"),
        delayMinutes (0), serverPath (list of server name), startTime, endTime, errorCode (None), errorMessage,
        and errorLine (raw log line with the rejection, e.g. SMTPI ... rejected: ...).
        Duplicates (same sender, recipient, errorMessage, file, line) are omitted.

    Behavior:
        - If neither sender nor recipient is provided, returns [].
        - Builds regex from re.escape(sender) and optionally re.escape(recipient) (OR if both set).
        - Uses _run_rg (or Python grep) to find candidate lines; then filters to lines containing " 1 " and "rejected".
        - Each line is parsed with _parse_rejection_line; sender/recipient are filled from search criteria when not in line.
        - For recipient-only search, only entries whose parsed recipient matches (case-insensitive) are included.
    """
    root = log_root if isinstance(log_root, Path) else Path(log_root)
    log.info("Step: find_front_end_rejections (sender=%r, recipient=%r, date=%s, time_range=%s)", sender, recipient, date_str, time_range)
    files = _get_ordered_files_for_merge(root, date_str, time_range=time_range) if date_str else []
    if not files:
        log.info("  No log files for date; skipping rejections")
        return []

    if not sender and recipient:
        pattern = re.escape(recipient)
    elif sender:
        pattern = re.escape(sender)
        if recipient:
            pattern += "|" + re.escape(recipient)
    else:
        return []
    hits = _run_rg(pattern, files, root, max_count=2000)

    results = []
    seen = set()

    for filepath, line_no, line_text in hits:
        if " 1 " not in line_text or "rejected" not in line_text:
            continue
        if not _line_in_time_range(line_text, time_range):
            continue
        rec = _parse_rejection_line(line_text)
        if not rec:
            continue
        # Prefer sender from search; fill from line
        if sender and not rec.get("sender"):
            rec["sender"] = sender
        if recipient and not rec.get("recipient"):
            rec["recipient"] = recipient
        # For recipient-only search, only include if recipient matches
        if not sender and recipient:
            if recipient.lower() not in rec.get("recipient", "").lower():
                continue
        key = (rec.get("sender") or "", rec.get("recipient") or "", rec.get("errorMessage"), filepath, line_no)
        if key in seen:
            continue
        seen.add(key)
        log_date = _date_from_filepath(filepath)
        ts = _parse_time_from_line(line_text)
        # Use local-time ISO (no Z) so frontend time filter matches user's 11h-12h
        time_part = f"{int(ts)//3600:02d}:{(int(ts)%3600)//60:02d}:{int(ts)%60:02d}" if ts is not None else "00:00:00"
        results.append({
            "id": f"rej-{filepath}-{line_no}",
            "sender": rec.get("sender") or "",
            "recipient": rec.get("recipient") or "",
            "direction": "Sent",
            "date": f"{log_date}T{time_part}",
            "status": "Rejected",
            "delayMinutes": 0,
            "serverPath": [_server_from_filepath(filepath)],
            "startTime": "",
            "endTime": "",
            "errorCode": None,
            "errorMessage": rec.get("errorMessage", ""),
            "errorLine": line_text,
        })
    log.info("  Rejections found: %d", len(results))
    return results


def find_accepted_mails_by_recipient(
    log_root: Path, recipient: str, date_str: Optional[str],
    time_range: Optional[tuple[int, int]] = None,
) -> list[dict]:
    """
    Find accepted (delivered/relayed) mails by recipient: DEQUEUER lines containing recipient, then trace back to sender.

    Purpose:
        When search is by recipient only (no sender), we find DEQUEUER lines that mention the recipient, collect their
        queue IDs, and for each queue ID search backward in the merged log stream to find QUEUE([id]) from <sender>.

    Parameters:
        log_root: Root directory containing FES server folders (Path or path-like).
        recipient: Recipient address (case-insensitive match in DEQUEUER lines).
        date_str: Date in YYYY-MM-DD; required. If None, returns [] (merge requires a date).

    Returns:
        List of dicts: id, sender (from QUEUE from), recipient (from DEQUEUER), dequeuerLine, status ("Success"),
        sourceFile, server, date (ISO local), delayMinutes (0), direction ("Sent"). One entry per DEQUEUER line found;
        queue IDs without a preceding QUEUE from line are skipped.

    Behavior:
        - Merges all FES log files for the date (ordered via _get_ordered_files_for_merge) into a single stream of (line, filepath).
        - Scans stream for "DEQUEUER" lines containing recipient (lowercase); extracts queue ID with regex.
        - For each queue ID, searches backward up to 1000 lines for QUEUE([qid]) from <sender>; uses that sender for the result.
        - Deduplicates by (qid, dequeuer_line). Time and date come from line timestamp and file date.
    """
    root = log_root if isinstance(log_root, Path) else Path(log_root)
    if not date_str:
        log.info("  No date specified; date required for merge")
        return []

    files = _get_ordered_files_for_merge(root, date_str, time_range=time_range)
    if not files:
        log.info("  No log files for date %s", date_str)
        return []

    log.info("Step: find_accepted_mails_by_recipient (recipient=%r, date=%s, time_range=%s) - %d FES files", recipient, date_str, time_range, len(files))
    recipient_lower = recipient.strip().lower()

    # Build merged stream
    merged: list[tuple[str, Path]] = []
    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    merged.append((ln.rstrip("\n"), filepath))
        except Exception as e:
            log.warning("  Could not read %s: %s", filepath, e)

    # Step 1: Find all DEQUEUER lines containing the recipient, collect queue IDs
    dequeuer_queue_ids = {}  # qid -> list of (dequeuer_line, filepath, index)
    for idx, (line, filepath) in enumerate(merged):
        if not _line_in_time_range(line, time_range):
            continue
        if "DEQUEUER" in line and recipient_lower in line.lower():
            m = re.search(r"DEQUEUER \[(\d+)\]", line)
            if m:
                qid = m.group(1)
                if qid not in dequeuer_queue_ids:
                    dequeuer_queue_ids[qid] = []
                dequeuer_queue_ids[qid].append((line, filepath, idx))

    log.info("  Found %d queue ID(s) with recipient in DEQUEUER lines", len(dequeuer_queue_ids))

    # Step 2: For each queue ID, trace back to find QUEUE from <sender>
    results = []
    seen = set()
    for qid, dequeuer_list in dequeuer_queue_ids.items():
        # Search backward from first DEQUEUER to find QUEUE from
        first_idx = dequeuer_list[0][2]
        sender_found = None
        # Look back up to 1000 lines (should be enough to find QUEUE from)
        search_limit = max(0, first_idx - 9000)
        for i in range(first_idx - 1, search_limit - 1, -1):
            ln, _ = merged[i]
            m = QUEUE_FROM_RE.search(ln)
            if m and m.group(1) == qid:
                sender_found = m.group(2)
                break

        if not sender_found:
            log.debug("  Queue %s: could not find QUEUE from line (searched back from index %d)", qid, first_idx)
            continue

        # Add all DEQUEUER lines for this queue
        for dequeuer_line, src_path, _ in dequeuer_list:
            key = (qid, dequeuer_line)
            if key not in seen:
                seen.add(key)
                rec = _extract_recipient_from_dequeuer(dequeuer_line)
                ts_match = TIME_RE.match(dequeuer_line.strip())
                time_part = f"{ts_match.group(1)}:{ts_match.group(2)}:{ts_match.group(3)}" if ts_match else "00:00:00"
                date_iso = f"{date_str}T{time_part}"
                results.append({
                    "id": f"q-{qid}-{src_path.name}-{first_idx}",
                    "sender": sender_found,
                    "recipient": rec,
                    "dequeuerLine": dequeuer_line,
                    "status": "Success",
                    "sourceFile": str(src_path.name),
                    "server": _server_from_filepath(str(src_path)),
                    "date": date_iso,
                    "delayMinutes": 0,
                    "direction": "Sent",
                })

    log.info("  Found %d DEQUEUER line(s) for recipient", len(results))
    return results


def find_accepted_mails(
    log_root: Path, sender: Optional[str], recipient: Optional[str], date_str: Optional[str],
    time_range: Optional[tuple[int, int]] = None,
) -> list[dict]:
    """
    Find accepted mails (QUEUE from <sender> followed by DEQUEUER lines) in merged FES logs; optional recipient filter.

    Purpose:
        For a given sender and date, merges all FES01/FES02 log files into one chronological stream, finds every
        QUEUE([id]) from <sender> line, then scans forward to collect all DEQUEUER [id] lines (optionally filtered by recipient).
        If sender is None but recipient is set, delegates to find_accepted_mails_by_recipient.

    Parameters:
        log_root: Root directory containing FES server folders (Path or path-like).
        sender: Sender address (case-insensitive). If None, recipient must be set (recipient-only search).
        recipient: Optional; if set, only DEQUEUER lines containing this recipient (case-insensitive) are included.
        date_str: Date in YYYY-MM-DD; required. None returns [].

    Returns:
        List of result dicts: id, sender, recipient, dequeuerLine, status ("Success"), sourceFile, server, date, delayMinutes, direction.
        Stops scanning forward for a queue ID when a line contains QUEUE([qid]) and "deleted".

    Behavior:
        - Merges files via _get_ordered_files_for_merge and builds merged list of (line, filepath).
        - Iterates with index i; when QUEUE_FROM_RE matches and sender matches, scans j from i+1 for DEQUEUER [qid] lines.
        - Deduplicates by (qid, dequeuer_line). Time/date from line and file stem.
    """
    if not sender and recipient:
        return find_accepted_mails_by_recipient(log_root, recipient, date_str, time_range=time_range)

    if not sender:
        return []

    root = log_root if isinstance(log_root, Path) else Path(log_root)
    if not date_str:
        log.info("  No date specified; date required for merge")
        return []

    files = _get_ordered_files_for_merge(root, date_str, time_range=time_range)
    if not files:
        log.info("  No log files for date %s", date_str)
        return []

    log.info("Step: find_accepted_mails (sender=%r, recipient=%r, date=%s, time_range=%s) - %d FES files", sender, recipient, date_str, time_range, len(files))
    sender_lower = sender.lower()
    recipient_lower = (recipient or "").strip().lower()

    # Build merged stream: list of (line, filepath) so we can search across file boundaries
    merged: list[tuple[str, Path]] = []
    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    merged.append((ln.rstrip("\n"), filepath))
        except Exception as e:
            log.warning("  Could not read %s: %s", filepath, e)

    results = []
    seen = set()
    i = 0
    while i < len(merged):
        line, filepath = merged[i]
        m = QUEUE_FROM_RE.search(line)
        if not m:
            i += 1
            continue

        qid = m.group(1)
        from_sender = m.group(2)
        if sender_lower not in from_sender.lower():
            i += 1
            continue

        # Found from <sender> - iterate forward in merged stream (can cross files), collect ALL DEQUEUER lines
        j = i + 1
        while j < len(merged):
            ln, src_path = merged[j]
            if f"DEQUEUER [{qid}]" in ln:
                dequeuer_line = ln
                if not _line_in_time_range(dequeuer_line, time_range):
                    j += 1
                    continue
                if recipient_lower:
                    if recipient_lower not in dequeuer_line.lower():
                        j += 1
                        continue
                key = (qid, dequeuer_line)
                if key not in seen:
                    seen.add(key)
                    rec = _extract_recipient_from_dequeuer(dequeuer_line)
                    ts_match = TIME_RE.match(dequeuer_line.strip())
                    time_part = f"{ts_match.group(1)}:{ts_match.group(2)}:{ts_match.group(3)}" if ts_match else "00:00:00"
                    date_iso = f"{date_str}T{time_part}"
                    results.append({
                        "id": f"q-{qid}-{src_path.name}-{j}",
                        "sender": sender,
                        "recipient": rec,
                        "dequeuerLine": dequeuer_line,
                        "status": "Success",
                        "sourceFile": str(src_path.name),
                        "server": _server_from_filepath(str(src_path)),
                        "date": date_iso,
                        "delayMinutes": 0,
                        "direction": "Sent",
                    })
            if f"QUEUE([{qid}])" in ln and "deleted" in ln:
                break
            j += 1
        i += 1

    log.info("  Found %d DEQUEUER line(s)", len(results))
    return results


def _queue_id_from_accepted_result(result: dict) -> Optional[str]:
    """Extract queue ID from an accepted result (from id or dequeuerLine). Returns None if not found."""
    rid = result.get("id") or ""
    m = re.search(r"^q-(\d+)-", rid)
    if m:
        return m.group(1)
    line = result.get("dequeuerLine") or ""
    m = re.search(r"DEQUEUER \[(\d+)\]", line)
    return m.group(1) if m else None


def _backend_servers_from_dequeuer_line(line: str) -> list[str]:
    """
    If the DEQUEUER line says 'relayed via 10.46.96.20/.21/.22', return the corresponding
    backend server list to search (VIP01,VIP02 / GP01,GP02 / ML01,ML02). Otherwise return [].
    """
    if not line or "relayed via" not in line:
        return []
    m = re.search(r"relayed via\s+(\S+)", line)
    if not m:
        return []
    addr = m.group(1).strip()
    if addr == RELAY_VIP:
        return list(VIP_SERVERS)
    if addr == RELAY_GP:
        return list(GP_SERVERS)
    if addr == RELAY_ML:
        return list(ML_SERVERS)
    return []


def _is_delivery_success_line(line: str, qid: str) -> bool:
    """
    True if line contains the queue id and indicates delivery success: either
    'got:250 2.0.0 OK' or 'relayed via <host>' where host is not an internal relay (10.46.96.20/21/22).
    """
    if qid not in line:
        return False
    if "got:250" in line and "2.0.0" in line and "OK" in line:
        return True
    if "relayed via" in line:
        m = re.search(r"relayed via\s+(\S+)", line)
        if m:
            host = m.group(1).strip()
            if host not in (RELAY_VIP, RELAY_GP, RELAY_ML):
                return True
    return False


def _find_delivery_confirmation_in_backend(
    log_root: Path,
    date_str: str,
    time_range: Optional[tuple[int, int]],
    qid: str,
    servers: list[str],
) -> Optional[tuple[str, str, dict]]:
    """
    Search VIP/GP/ML log files for a line that confirms delivery for the given queue id
    (e.g. 'relayed via gmail-smtp-in.l.google.com' or 'got:250 2.0.0 OK').
    Returns (source_str, success_line, details) or None if not found.
    """
    if not date_str or not servers or not qid:
        return None
    root = Path(log_root)
    files = _get_log_files_for_servers(root, servers, date_str)
    if not files:
        return None
    # Search for lines containing [qid] and delivery success pattern
    pattern = re.escape(f"[{qid}]")
    hits = _run_rg(pattern, files, root, max_count=500)
    for filepath, line_no, line_text in hits:
        if not _line_in_time_range(line_text, time_range):
            continue
        if _is_delivery_success_line(line_text, qid):
            server = _server_from_filepath(str(filepath))
            source_str = f"{server} / {Path(filepath).name}" if server else Path(filepath).name
            details = {
                "file": Path(filepath).name,
                "lineNo": line_no,
                "serverFolder": server,
                "line": line_text,
                "lineText": line_text,
            }
            return (source_str, line_text, details)
    return None


def _enrich_accepted_with_delivery_confirmation(
    results: list[dict],
    log_root: Path,
    date_str: Optional[str],
    time_range: Optional[tuple[int, int]],
) -> None:
    """
    For each accepted (Success) result, if the DEQUEUER line shows relay to VIP/GP/ML,
    search those servers for the final delivery line and set delivery_source, delivery_success_line,
    and deliveryConfirmationLogs on the result. Mutates results in place.
    """
    if not date_str:
        return
    for r in results:
        if r.get("status") != "Success":
            continue
        qid = _queue_id_from_accepted_result(r)
        if not qid:
            continue
        servers = _backend_servers_from_dequeuer_line(r.get("dequeuerLine") or "")
        if not servers:
            continue
        found = _find_delivery_confirmation_in_backend(log_root, date_str, time_range, qid, servers)
        if found:
            source_str, success_line, details = found
            r["delivery_source"] = source_str
            r["delivery_success_line"] = success_line
            r["deliveryConfirmationLogs"] = [details]


def search_logs(
    log_root: Path,
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    date_str: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> tuple[list[dict], list[str]]:
    """
    Main entry: time-bounded FES search, map relay IP to folders, find success in mapped folders only.
    Returns (results, stages). Each result: timestamp, sender, receiver, delivery_id, fes_log_line,
    mapped_server_folder, success_message; plus id, status, recipient for frontend compat.
    Validation (date, start/end time ≤5h, sender or recipient) must be done before calling.
    """
    log.info("[ENTER] search_logs input=log_root=%s sender=%s recipient=%s date_str=%s start_time=%s end_time=%s",
             log_root, sender, recipient, date_str, start_time, end_time)
    stages = []
    date_norm = _normalize_date(date_str)
    time_range = None
    if start_time and end_time:
        start_min = _parse_time_to_minutes(start_time)
        end_min = _parse_time_to_minutes(end_time)
        if start_min is not None and end_min is not None and start_min <= end_min:
            time_range = (start_min, end_min)

    if not date_norm or not time_range:
        log.info("[EXIT] search_logs output=([], ['FES filtering', 'Server mapping', 'Delivery confirmation'])")
        return [], ["FES filtering", "Server mapping", "Delivery confirmation"]

    stages.append("FES filtering")
    fes_hits = _search_fes_time_bounded(log_root, date_norm, time_range, sender, recipient)
    log.info("  FES time-bounded hits: %d", len(fes_hits))

    stages.append("Server mapping")
    stages.append("Delivery confirmation")

    # Downstream: search by delivery_id only, in mapped folder only.
    # IMPORTANT: do NOT restrict by UI time_range, because backend servers may log
    # the final delivery a few minutes before/after the FES relay window or have
    # slightly skewed clocks (e.g. VIP shows 10:56 while FES shows 11:02).
    success_by_queue_id: dict[str, tuple[str, str, list[str]]] = {}
    rejection_by_queue_id: dict[str, tuple[str, str, list[str]]] = {}
    groups_with_did = _group_fes_hits_by_server_with_delivery_id(fes_hits)
    for group_name, servers_list, delivery_ids_set, delivery_id_to_queue_id in groups_with_did:
        log.info(
            "  Group %s: %d delivery ID(s) (search by delivery_id, time_range=None / full day)",
            group_name,
            len(delivery_ids_set),
        )
        # Use full-day search for downstream servers so that valid delivery confirmations
        # are not missed when their timestamps fall slightly outside the FES time window.
        found_by_did = _search_downstream_by_delivery_id(
            log_root,
            date_norm,
            servers_list,
            delivery_ids_set,
            time_range=None,
        )
        for did, (folder, msg, lines) in found_by_did.items():
            qid = delivery_id_to_queue_id.get(did)
            if qid:
                success_by_queue_id[qid] = (folder, msg, lines)
                for line in lines:
                    log.info("  [qid=%s did=%s] %s | %s", qid, did, folder, line)

        # For any delivery IDs that did not yield a success indicator, try to find
        # a rejection indicator in downstream logs so each mapped log has either
        # a success or a rejection reason.
        remaining_dids = {did for did in delivery_ids_set if did not in found_by_did}
        if remaining_dids:
            found_rejections = _search_downstream_rejections_by_delivery_id(
                log_root,
                date_norm,
                servers_list,
                remaining_dids,
            )
            for did, (folder, msg, lines) in found_rejections.items():
                qid = delivery_id_to_queue_id.get(did)
                if qid and qid not in rejection_by_queue_id:
                    rejection_by_queue_id[qid] = (folder, msg, lines)
                    for line in lines:
                        log.info("  [qid=%s did=%s] %s | REJECT %s", qid, did, folder, line)

    results = []
    for i, hit in enumerate(fes_hits):
        qid = hit.get("queue_id", "")
        mapped_folder_str = ""
        success_message = None
        rejection_message = None
        rejection_log_lines: list[str] = []
        success_log_lines: list[str] = []
        dequeuer_line_text = (hit.get("dequeuer_line") or "")
        is_discarded_without_processing = "message discarded without processing" in dequeuer_line_text.lower()
        if hit.get("local_delivery_success") and not is_discarded_without_processing:
            success_message = "Delivered to local mailbox"
            success_log_lines = [dequeuer_line_text] if dequeuer_line_text else []
        elif qid and qid in success_by_queue_id:
            mapped_folder_str, success_message, success_log_lines = success_by_queue_id[qid]
        elif qid and qid in rejection_by_queue_id:
            mapped_folder_str, rejection_message, rejection_log_lines = rejection_by_queue_id[qid]
        elif hit.get("relay_ip"):
            mapped_folder_str = ",".join(_relay_ip_to_folders(hit.get("relay_ip") or ""))
        delivery_line = hit.get("dequeuer_line_mapped") or ""
        r = {
            "id": f"v-{qid or i}-{hit.get('fes_file', '')}-{i}",
            "queue_id": qid,
            "timestamp": hit.get("timestamp", ""),
            "sender": hit.get("sender", ""),
            "receiver": hit.get("receiver", ""),
            "recipient": hit.get("receiver", ""),
            "delivery_id": hit.get("delivery_id"),
            "fes_log_line": hit.get("fes_log_line", ""),
            "dequeuer_line": hit.get("dequeuer_line", ""),
            "delivery_line": delivery_line,
            "mapped_server_folder": mapped_folder_str,
            "success_message": success_message or "",
            "success_log_lines": success_log_lines,
            "errorMessage": rejection_message or "",
            "errorLine": rejection_log_lines[0] if rejection_log_lines else "",
            # Treat lines with "message discarded without processing" as Pending (yellow),
            # otherwise anything without a confirmed delivery is Rejected (not pending).
            "status": "Pending"
            if is_discarded_without_processing
            else "Success"
            if (success_message or hit.get("local_delivery_success"))
            else "Rejected",
            "date": hit.get("timestamp", ""),
            "direction": "Sent",
        }
        results.append(r)

    rejections = find_front_end_rejections(log_root, sender or "", recipient, date_norm, time_range=time_range) if sender else []
    for r in rejections:
        r["id"] = r.get("id", "")
        results.append(r)
    log.info("Step: combined %d verification + %d rejections -> %d total", len(fes_hits), len(rejections), len(results))
    log.info("[EXIT] search_logs output=(results count=%d, stages=%s)", len(results), stages)
    return results, stages


# =============================================================================
# NOTES — Built-in and standard library functions used in this module
# =============================================================================
#
# This section documents every predefined or built-in function, method, and
# constant used in the backend parser so that behavior is fully traceable.
#
# --- logging (standard library) ---
#   logging.getLogger(name)
#       Returns a logger for the given module name (__name__). Used to obtain
#       the module-level `log` object for info/debug/warning messages without
#       printing to stdout.
#
#   Logger.info(msg, *args), Logger.debug(msg, *args), Logger.warning(msg, *args)
#       Log a message at the given level; msg can use %-style placeholders
#       (e.g. %s, %d, %r) and args are substituted. No return value.
#
# --- os (standard library) ---
#   os.name
#       String indicating OS: "nt" for Windows, "posix" for Unix-like. Used to
#       decide whether to look for rg in Windows-specific paths.
#
#   os.environ.get(key, default=None)
#       Returns the value of environment variable `key`, or `default` if not set.
#       Used for LOG_ROOT, RG_PATH, ProgramFiles, LOCALAPPDATA, USERPROFILE, etc.
#
# --- re (standard library) ---
#   re.compile(pattern, flags=0)
#       Compiles a regex pattern string into a Pattern object for repeated use.
#       flags: re.IGNORECASE, re.MULTILINE, etc. Raises re.error on invalid pattern.
#
#   re.match(pattern, string)
#       Try to match the pattern at the start of the string. Returns a Match
#       object or None. (Also used as method: TIME_RE.match(line).)
#
#   re.search(pattern, string)
#       Scan the string for the first match. Returns a Match object or None.
#
#   re.escape(string)
#       Return a string with all non-alphanumeric characters backslash-escaped,
#       so it can be used as a literal in a regex.
#
#   re.error
#       Exception raised when a regex pattern is invalid (e.g. unbalanced parens).
#
#   re.IGNORECASE (re.I)
#       Flag: match letters case-insensitively.
#
#   re.MULTILINE (re.M)
#       Flag: ^ and $ match at line boundaries within the string.
#
#   Match.group(i), Match.group(1), ...
#       Return the i-th capturing group (1-based). group(0) is the full match.
#
# --- shutil (standard library) ---
#   shutil.which(name, path=None)
#       Search for executable `name` in PATH (or optional path). Returns the
#       full path string or None. Used to find "rg" on the system.
#
# --- subprocess (standard library) ---
#   subprocess.run(args, *, capture_output, text, timeout, cwd)
#       Run the command in args (list). capture_output=True captures stdout/stderr;
#       text=True decodes them as str. timeout=120 raises TimeoutExpired after 120s.
#       Returns a CompletedProcess with .stdout, .stderr, .returncode.
#
#   subprocess.TimeoutExpired
#       Exception raised when the process does not finish within the timeout.
#
# --- pathlib.Path (standard library) ---
#   Path(path) / name
#       Build a path by joining with the given segment(s). Overloads /.
#
#   Path.resolve()
#       Return the absolute path, resolving symlinks and "..". Used for LOG_ROOT.
#
#   Path.is_file(), Path.is_dir()
#       Return True if the path exists and is a file or directory, respectively.
#
#   Path.is_absolute()
#       True if the path is absolute (e.g. starts with / or drive letter).
#
#   Path.exists()
#       True if the path exists on the filesystem.
#
#   Path.cwd()
#       Class method: return the current working directory as a Path.
#
#   Path.iterdir()
#       Yield path objects for entries in the directory. Does not recurse.
#
#   Path.stem
#       Final component without suffix (e.g. "2026-01-29_10-52" for "2026-01-29_10-52.log").
#
#   Path.suffix
#       File extension (e.g. ".log").
#
#   Path.name
#       Final component (filename including extension).
#
#   Path.parts
#       Tuple of path components (e.g. ("C:", "Log-CG", "FES01", "2026-01-29.log")).
#
#   Path(...) when given str
#       Path can be constructed from a string; Path(filepath) normalizes slashes.
#
# --- typing ---
#   Optional[X]
#       Type alias for Union[X, None]. Used for parameters and return types that may be None.
#
# --- Built-in functions ---
#   open(file, mode="r", encoding=..., errors=...)
#       Open a file. encoding="utf-8", errors="ignore" skips invalid UTF-8 bytes.
#       Returns a file object; used with "with" for automatic close.
#
#   len(seq)
#       Return the number of items in a sequence (list, str, etc.).
#
#   range(start, stop[, step])
#       Immutable sequence of integers from start to stop (exclusive). Used for
#       backward iteration (e.g. range(first_idx - 1, search_limit - 1, -1)).
#
#   enumerate(iterable, start=0)
#       Yield (index, item) pairs. start=1 used for 1-based line numbers.
#
#   int(x), float(x)
#       Convert to integer or float. int("12") -> 12; used for line numbers and time math.
#
#   str(x)
#       Convert to string. Used to ensure filepath is str in result tuples.
#
#   isinstance(obj, classinfo)
#       True if obj is an instance of classinfo (e.g. isinstance(filepath, Path)).
#
#   sorted(iterable, key=None)
#       Return a new sorted list. key=sort_key used to order log files by date/time.
#
#   min(a, b), max(a, b)
#       Return the smaller or larger of two values. Used to clamp slice indices.
#
#   sum(), list(), set(), dict()
#       sum not used; list() builds lists; set() for seen sets; dict() for by_id.
#
# --- str methods ---
#   str.strip([chars])
#       Return a copy with leading/trailing whitespace (or chars) removed.
#
#   str.split(sep=None, maxsplit=-1)
#       Split by sep; maxsplit limits splits (e.g. line.split(":", 2) -> at most 3 parts).
#
#   str.startswith(prefix), str.endswith(suffix)
#       True if the string starts or ends with the given substring.
#
#   str.lower()
#       Return a copy in lowercase (for case-insensitive comparison).
#
#   str.format(*args, **kwargs)
#       Format string with {}-style placeholders. Not used; f-strings used instead.
#
#   str.rstrip([chars])
#       Remove trailing characters (default whitespace). Used as line.rstrip("\\n").
#
# --- list methods ---
#   list.append(x)
#       Add x to the end of the list. In-place; returns None.
#
#   list.extend(iterable) — not used
#   list comprehension [x for x in ... if ...]
#       Build a list from an iterable, optionally filtering.
#
# --- dict methods ---
#   dict.get(key, default=None)
#       Return value for key, or default if key is missing. Used to avoid KeyError.
#
#   dict[key] = value
#       Set or create key. Used for by_id[r["id"]] = r and result dict construction.
#
#   "key" in dict
#       True if key is in the dictionary.
#
# --- set methods ---
#   set.add(elem)
#       Add element to the set. Used for seen.add(key).
#
#   elem in set
#       True if elem is in the set. Used for deduplication (key in seen).
#
# --- file object (from open) ---
#   f.readlines()
#       Read all lines into a list; each element includes the newline.
#
#   for line in f:
#       Iterate over file line by line (memory-efficient). line includes "\\n".
#
# --- Other ---
#   tuple unpacking: (a, b) = x; for a, b in enumerate(...)
#   f-strings: f"{x}" for string interpolation.
#   Boolean short-circuit: "x" in line and "y" in line.
#   Slice: lines[start:end]; list[:max_count].
#   try/except: catch FileNotFoundError, TimeoutExpired, Exception, ValueError, IndexError.
#   with statement: ensures file (and subprocess resources) are released.
#
# --- Unused import ---
#   datetime is imported but not used in this module; may be reserved for future timestamp formatting or filtering.
#
