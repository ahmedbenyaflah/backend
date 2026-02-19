# Email Log Search API

FastAPI backend that searches Log-CG (FES01/02, VIP*, GP*, ML*) using ripgrep (rg) or grep, with a pure-Python fallback.

**Full workflow, file naming, and examples:** see [WORKFLOW.md](../WORKFLOW.md) at repo root.

## Setup

```bash
cd backend
pip install -r requirements.txt
```

- **LOG_ROOT**: Log-CG directory (default: parent dir `../Log-CG`).
- **RG_PATH**: Full path to `rg.exe` (ripgrep) if not in PATH. Search uses rg when found, else a slow Python fallback.

### Installing ripgrep (rg) so search is fast

If you see **"ripgrep (rg) not found"** in the logs, install rg so the backend can search large logs quickly.

**Windows (PowerShell):**
```powershell
# Option A: Scoop (if you use it)
scoop install ripgrep

# Option B: Chocolatey (if you use it)
choco install ripgrep

# Option C: Manual – download from https://github.com/BurntSushi/ripgrep/releases
# Unzip and add the folder containing rg.exe to your PATH, or set RG_PATH:
$env:RG_PATH = "C:\path\to\ripgrep-14.x.x-x86_64-pc-windows-msvc\rg.exe"
```

**macOS:** `brew install ripgrep`  
**Linux:** `sudo apt install ripgrep` (or equivalent).

After installing, restart the backend. It will try: `RG_PATH` → `PATH` → common Windows locations (Program Files, Scoop, Cargo).

## Run

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

## Endpoints

- **GET /api/search?sender=...&recipient=...&date=...** – Search by sender (required), optional recipient and date. **Date** can be `YYYY-MM-DD`, `29/01`, `29-01`, etc. Returns `{ "results": [ ... ] }` with log entries (sender, recipient, date, status, delayMinutes, serverPath, errorMessage, etc.).
- **GET /api/health** – Health check.

## Log logic (parser.py)

- **Front-end validation**: Searches FES01/02 for sender; captures front-end rejections (SMTPI/ROUTER lines with `rejected:`) and returns status Error with errorMessage.
- **Accepted mail**: Searches **all probable places** – FES01, FES02, VIP01, VIP02, GP01, GP02, ML01, ML02 – for `QUEUE([id]) from <sender>`, then traces DEQUEUER and SMTP sent to get relay IP. With no recipient you get all queues for that sender (including those to marwen.mce@gmail.com); with recipient you get only matching queues.
- **Routing**: Relay IP .20 → VIP01, .21 → GP01, .22 → ML01; otherwise "Relayed to [IP]".
- **Delay**: Final timestamp minus initial timestamp (minutes).
- **Server path**: Server where the queue was found (e.g. FES02, ML01) then next hop from relay.






Log a warning when rejections hit 2,000 or downstream hits reach 100,000, so operators know truncation occurred.
I can propose concrete code changes for these three items if you want to implement them.


00:08:20.111 4 SMTP-004929(labanquepostale.fr) rsp: 250 ok:  Message 99811793 accepted
00:08:20.111 2 SMTP-004929(labanquepostale.fr) [113457753] sent [197.26.11.132]:44905 -> [178.213.67.13]:25, got:250 ok:  Message 99811793 accepted
00:08:20.111 4 SMTP(labanquepostale.fr) [113457753] batch relayed
00:08:20.111 2 DEQUEUER [113457753] SMTP(labanquepostale.fr)cecile.rageau@labanquepostale.fr relayed: relayed via rpi0i692.laposte.fr
00:08:20.111 4 QUEUE([113457753]) dequeued, nTotal=727
00:08:20.111 4 DEQUEUER [113457753] moved out of delayed queue
00:08:20.111 4 DEQUEUER [113457753] placed into empty 'immediate' queue
00:08:20.111 4 SMTP-004929(labanquepostale.fr) cmd: QUIT
00:08:20.111 4 DEQUEUER-000043 [113457753] processing
00:08:20.112 2 QUEUE([113457753]) deleted
