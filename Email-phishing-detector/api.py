"""
PhishGuard — FastAPI Backend
Run:  uvicorn api:app --reload --port 8000
"""

import asyncio
import json
import email
import os
import sqlite3
import threading
import time
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()

app = FastAPI(
    title="PhishGuard API",
    description="Automated Phishing Email Detection and Response System",
    version="2.1.0",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allows the dashboard (any origin during dev) to call this API.
# In production, replace ["*"] with your exact frontend URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve dashboard.html as static file at / ─────────────────────────────────
# Put dashboard.html in the same folder as api.py, or adjust the path.
import pathlib
_here = pathlib.Path(__file__).parent
if (_here / "dashboard.html").exists():
    app.mount("/static", StaticFiles(directory=str(_here)), name="static")


# ─────────────────────────────────────────────────────────────────────────────
#  In-memory state  (survives as long as the server process runs)
# ─────────────────────────────────────────────────────────────────────────────
class AppState:
    def __init__(self):
        self.scanned      = 0
        self.threats      = 0
        self.header_fails = 0
        self.clean        = 0
        self.vt_hits      = 0
        self.spf_fails    = 0
        self.dkim_fails   = 0
        self.scan_history: list[dict] = []   # [{safe, threat, ts}, ...]
        self.scan_running = False
        self.scheduler_running = False
        self.scheduler_interval = int(os.getenv("POLL_INTERVAL", 5))
        self._scheduler_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        # Settings (runtime-editable)
        self.threshold     = 3
        self.enable_spf    = True
        self.enable_dkim   = True
        self.enable_vt     = True
        self.enable_quarantine = True
        self.enable_alerts = True
        # Multi-account registry
        # Each: { id, label, email, password, imap_server, imap_port,
        #         enabled, last_scan, last_error, scanned, threats }
        self.accounts: list[dict] = []
        self._acct_lock = threading.Lock()

state = AppState()


# ─────────────────────────────────────────────────────────────────────────────
#  WebSocket log broadcaster
# ─────────────────────────────────────────────────────────────────────────────
class LogBroadcaster:
    def __init__(self):
        self._clients: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._clients.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._clients = [c for c in self._clients if c != ws]

    async def broadcast(self, msg: dict):
        """Send a JSON message to every connected WebSocket client."""
        dead = []
        for ws in list(self._clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

broadcaster = LogBroadcaster()


def emit(level: str, text: str, data: dict = None):
    """
    Thread-safe log emit.  Pushes a message to all WS clients AND
    prints to console.  Call from sync code (scan threads).
    """
    payload = {
        "type": "log",
        "level": level,          # info | ok | warn | err
        "text": text,
        "ts": datetime.now().strftime("%H:%M:%S"),
        **(data or {}),
    }
    print(f"[{payload['ts']}] [{level.upper():4}] {text}")
    # Schedule the coroutine on the event loop from a background thread
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(broadcaster.broadcast(payload), loop)
    except RuntimeError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Database helpers  (reads from phishing_alerts.db created by logger.py)
# ─────────────────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("DB_PATH", "phishing_alerts.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_tables():
    """
    Create tables if they don't exist, and migrate the old 3-column
    flagged_emails table (created by the original logger.py) to the
    full schema that api.py expects.
    """
    with get_db_connection() as conn:

        # ── Step 1: create the full table if it doesn't exist at all ─────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flagged_emails (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                sender    TEXT,
                subject   TEXT,
                body      TEXT,
                spf       TEXT    DEFAULT 'unknown',
                dkim      TEXT    DEFAULT 'unknown',
                vt_hit    INTEGER DEFAULT 0,
                score     INTEGER DEFAULT 0,
                flags     TEXT    DEFAULT '[]',
                timestamp TEXT    DEFAULT (datetime('now','localtime')),
                account   TEXT    DEFAULT 'default'
            )
        """)

        # ── Step 2: migrate — add any columns the old table is missing ────────
        # PRAGMA table_info returns one row per column; we collect existing names.
        existing = {
            row[1]  # column name is index 1
            for row in conn.execute("PRAGMA table_info(flagged_emails)")
        }
        migrations = [
            ("spf",       "TEXT    DEFAULT 'unknown'"),
            ("dkim",      "TEXT    DEFAULT 'unknown'"),
            ("vt_hit",    "INTEGER DEFAULT 0"),
            ("score",     "INTEGER DEFAULT 0"),
            ("flags",     "TEXT    DEFAULT '[]'"),
            ("timestamp", "TEXT    DEFAULT ''"),
            ("account",   "TEXT    DEFAULT 'default'"),
        ]
        for col_name, col_def in migrations:
            if col_name not in existing:
                conn.execute(
                    f"ALTER TABLE flagged_emails ADD COLUMN {col_name} {col_def}"
                )
                print(f"[migrate] Added column '{col_name}' to flagged_emails.")

        # ── Step 3: SQLite has no AUTOINCREMENT retro-fit, but the old table
        #    uses rowid implicitly — expose it as 'id' via a view so existing
        #    rows are still queryable by id without rebuilding the table. ──────
        if "id" not in existing:
            # The old table has no explicit 'id' column. Rebuild it properly:
            # copy → drop → rename, preserving all old rows.
            print("[migrate] Rebuilding flagged_emails to add id primary key…")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS _flagged_emails_new (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender    TEXT,
                    subject   TEXT,
                    body      TEXT,
                    spf       TEXT    DEFAULT 'unknown',
                    dkim      TEXT    DEFAULT 'unknown',
                    vt_hit    INTEGER DEFAULT 0,
                    score     INTEGER DEFAULT 0,
                    flags     TEXT    DEFAULT '[]',
                    timestamp TEXT    DEFAULT (datetime('now','localtime'))
                )
            """)
            conn.execute("""
                INSERT INTO _flagged_emails_new
                    (sender, subject, body, spf, dkim, vt_hit, score, flags, timestamp)
                SELECT
                    sender, subject, body,
                    COALESCE(spf,  'unknown'),
                    COALESCE(dkim, 'unknown'),
                    COALESCE(vt_hit, 0),
                    COALESCE(score,  0),
                    COALESCE(flags,  '[]'),
                    COALESCE(timestamp, datetime('now','localtime'))
                FROM flagged_emails
            """)
            conn.execute("DROP TABLE flagged_emails")
            conn.execute(
                "ALTER TABLE _flagged_emails_new RENAME TO flagged_emails"
            )
            print("[migrate] Migration complete — all old rows preserved.")

        # ── Step 4: scan_runs table ───────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT,
                scanned   INTEGER,
                threats   INTEGER,
                clean     INTEGER
            )
        """)
        conn.commit()


ensure_tables()


# ─────────────────────────────────────────────────────────────────────────────
#  Accounts — persistent storage helpers
# ─────────────────────────────────────────────────────────────────────────────
def _ensure_accounts_table():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                label       TEXT    DEFAULT '',
                email       TEXT    NOT NULL UNIQUE,
                password    TEXT    NOT NULL,
                imap_server TEXT    DEFAULT 'imap.gmail.com',
                imap_port   INTEGER DEFAULT 993,
                enabled     INTEGER DEFAULT 1,
                last_scan   TEXT    DEFAULT '',
                last_error  TEXT    DEFAULT '',
                scanned     INTEGER DEFAULT 0,
                threats     INTEGER DEFAULT 0
            )
        """)
        conn.commit()


def _load_accounts_from_db():
    _ensure_accounts_table()
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM accounts").fetchall()
    with state._acct_lock:
        state.accounts = [dict(r) for r in rows]
    print(f"[accounts] Loaded {len(state.accounts)} account(s) from DB.")


_ensure_accounts_table()
_load_accounts_from_db()


def log_threat_to_db(email_info: dict, result: dict):
    """Persist a detected threat to SQLite."""
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO flagged_emails
               (sender, subject, body, spf, dkim, vt_hit, score, flags, timestamp, account)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                email_info.get("from", ""),
                email_info.get("subject", ""),
                email_info.get("body", "")[:500],
                result.get("spf", "unknown"),
                result.get("dkim", "unknown"),
                int(result.get("vt_hit", False)),
                result.get("total_score", 0),
                json.dumps(result.get("flags", [])),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                result.get("account", "default"),
            ),
        )
        conn.commit()


def log_scan_run(scanned: int, threats: int, clean: int):
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO scan_runs (ts, scanned, threats, clean) VALUES (?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scanned, threats, clean),
        )
        conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  Core scan logic  (runs in a background thread)
# ─────────────────────────────────────────────────────────────────────────────
def run_scan_thread(max_emails: int = 20, folder: str = "inbox", mode: str = "full"):
    """
    Multi-account scan cycle.
    Connects to every enabled account, fetches unread emails from each,
    runs SPF/DKIM/VirusTotal checks, and emits real-time WebSocket log events.
    Falls back to the single .env account if no accounts are registered.
    """
    if state.scan_running:
        emit("warn", "Scan already running — skipping.")
        return

    state.scan_running = True
    scan_safe = 0
    scan_threats = 0

    try:
        from email_handler import fetch_emails_from_all, connect_to_email, fetch_emails

        # ── Build account list ────────────────────────────────────────────────
        with state._acct_lock:
            accounts = [a for a in state.accounts if a.get("enabled", True)]

        if accounts:
            emit("info", f"Scanning {len(accounts)} account(s)…")
            all_emails = fetch_emails_from_all(accounts, folder=folder, max_emails=max_emails)
        else:
            # Fallback: use single .env account
            emit("info", "No accounts registered — using .env credentials.")
            mail = connect_to_email()
            emit("ok", "IMAP login successful.")
            raw = fetch_emails(mail, folder=folder, max_emails=max_emails)
            for e in raw:
                e["account"]  = "default"
                e["mail_obj"] = mail
            all_emails = raw

        if not all_emails:
            emit("info", "No unread emails found across all accounts.")
            state.scan_running = False
            return

        emit("info", f"{len(all_emails)} email(s) total — starting analysis.")

        for i, email_info in enumerate(all_emails, 1):
            acct_tag = email_info.get("account", "?")
            emit("info", f"── [{acct_tag}] Email {i}/{len(all_emails)}: {email_info['from']}")

            result = {"spf": "skipped", "dkim": "skipped", "vt_hit": False,
                      "total_score": 0, "flags": []}

            # ── SPF + DKIM ────────────────────────────────────────────────
            if mode in ("full", "headers") and (state.enable_spf or state.enable_dkim):
                from spf_dkim_check import run_spf_dkim_checks
                header_result = run_spf_dkim_checks(email_info)
                result.update(header_result)
                result["total_score"] = header_result["score"]
                result["flags"]       = list(header_result["flags"])

                spf_lvl  = "ok" if result["spf"] == "pass" else "warn" if result["spf"] == "softfail" else "err"
                dkim_lvl = "ok" if result["dkim"] == "pass" else "warn"
                emit(spf_lvl,  f"  SPF  : {result['spf']}")
                emit(dkim_lvl, f"  DKIM : {result['dkim']}")

                if result["spf"] != "pass":
                    state.spf_fails += 1
                if result["dkim"] != "pass":
                    state.dkim_fails += 1
                if result["spf"] != "pass" or result["dkim"] != "pass":
                    state.header_fails += 1

            # ── VirusTotal ────────────────────────────────────────────────
            if mode in ("full", "urls") and state.enable_vt:
                from phishing_detection import check_url_virustotal
                vt_hit = check_url_virustotal(email_info["body"])
                result["vt_hit"] = vt_hit
                if vt_hit:
                    result["total_score"] += 5
                    result["flags"].append("Malicious URL detected by VirusTotal")
                    state.vt_hits += 1
                emit(
                    "err" if vt_hit else "ok",
                    f"  VirusTotal : {'MALICIOUS URL FOUND' if vt_hit else 'clean'}",
                )

            # ── Verdict ───────────────────────────────────────────────────
            state.scanned += 1
            is_threat = result["total_score"] >= state.threshold

            if is_threat:
                emit("err",
                     f"  THREAT (score {result['total_score']}) — quarantining.",
                     {"event": "threat", "from": email_info["from"],
                      "subject": email_info["subject"], **result})

                if state.enable_quarantine:
                    try:
                        from quarantine import quarantine_email
                        _mail_conn = email_info.get("mail_obj")
                        if _mail_conn:
                            quarantine_email(_mail_conn, email_info["id"])
                        else:
                            emit("warn", "  Quarantine skipped: no mail connection on email.")
                    except Exception as e:
                        emit("warn", f"  Quarantine failed: {e}")

                if state.enable_alerts:
                    try:
                        from alert import send_alert_email
                        send_alert_email(
                            subject=f"Phishing Alert — score {result['total_score']}",
                            message=_build_alert_body(email_info, result),
                        )
                    except Exception as e:
                        emit("warn", f"  Alert email failed: {e}")

                # tag account for DB storage
                result["account"] = email_info.get("account", "default")
                log_threat_to_db(email_info, result)

                # per-account counters
                acct_email = email_info.get("account")
                if acct_email:
                    with state._acct_lock:
                        for a in state.accounts:
                            if a["email"] == acct_email:
                                a["threats"] = a.get("threats", 0) + 1
                                a["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                break

                state.threats += 1
                scan_threats += 1

            else:
                emit("ok", f"  Clean (score {result['total_score']})",
                     {"event": "clean", "from": email_info["from"],
                      "subject": email_info["subject"]})
                state.clean += 1
                scan_safe += 1
                acct_email = email_info.get("account")
                if acct_email:
                    with state._acct_lock:
                        for a in state.accounts:
                            if a["email"] == acct_email:
                                a["scanned"] = a.get("scanned", 0) + 1
                                a["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                break

        # ── Wrap up ───────────────────────────────────────────────────────
        state.scan_history.append({
            "ts": datetime.now().strftime("%H:%M"),
            "safe": scan_safe,
            "threat": scan_threats,
        })
        log_scan_run(len(email), scan_threats, scan_safe)
        emit("ok",
             f"Scan complete — {scan_threats} threat(s), {scan_safe} clean.",
             {"event": "scan_done", "threats": scan_threats, "clean": scan_safe})

    except Exception as exc:
        emit("err", f"Scan error: {exc}")
    finally:
        state.scan_running = False


def _build_alert_body(email_info: dict, result: dict) -> str:
    lines = [
        f"Phishing threat detected — score {result['total_score']}",
        f"From    : {email_info['from']}",
        f"Subject : {email_info['subject']}",
        "",
        "Issues:",
    ] + [f"  • {f}" for f in result.get("flags", [])] + [
        "",
        f"SPF : {result.get('spf','?')}",
        f"DKIM: {result.get('dkim','?')}",
        f"VT  : {'hit' if result.get('vt_hit') else 'clean'}",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Scheduler (background thread)
# ─────────────────────────────────────────────────────────────────────────────
def _scheduler_loop(interval_minutes: int, stop_event: threading.Event):
    emit("info", f"Auto-scheduler started — every {interval_minutes} min.")
    run_scan_thread()
    while not stop_event.wait(timeout=interval_minutes * 60):
        emit("info", "Scheduler tick — starting scan.")
        run_scan_thread()
    emit("info", "Scheduler stopped.")


# ─────────────────────────────────────────────────────────────────────────────
#  Pydantic request/response models
# ─────────────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    mode:       str = "full"        # full | headers | urls
    folder:     str = "inbox"
    max_emails: int = 20

class SchedulerRequest(BaseModel):
    interval_minutes: int = 5

class SettingsRequest(BaseModel):
    threshold:          int  = 3
    enable_spf:         bool = True
    enable_dkim:        bool = True
    enable_vt:          bool = True
    enable_quarantine:  bool = True
    enable_alerts:      bool = True

class ConfigRequest(BaseModel):
    EMAIL_ADDRESS:      str = ""
    EMAIL_PASSWORD:     str = ""
    IMAP_SERVER:        str = "imap.gmail.com"
    IMAP_PORT:          int = 993
    ALERT_EMAIL:        str = ""
    SMTP_USER:          str = ""
    SMTP_PASSWORD:      str = ""
    VIRUSTOTAL_API_KEY: str = ""

class AccountAddRequest(BaseModel):
    label:       str = ""
    email:       str
    password:    str
    imap_server: str = "imap.gmail.com"
    imap_port:   int = 993
    enabled:     bool = True

class AccountUpdateRequest(BaseModel):
    label:       str  = ""
    enabled:     bool = True
    imap_server: str  = "imap.gmail.com"
    imap_port:   int  = 993


# ─────────────────────────────────────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "PhishGuard API", "version": "2.1.0"}


@app.get("/health", tags=["Health"])
def health():
    return {
        "status":           "ok",
        "scan_running":     state.scan_running,
        "scheduler_running":state.scheduler_running,
        "db_path":          DB_PATH,
    }


# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats", tags=["Monitor"])
def get_stats():
    return {
        "scanned":      state.scanned,
        "threats":      state.threats,
        "header_fails": state.header_fails,
        "clean":        state.clean,
        "vt_hits":      state.vt_hits,
        "spf_fails":    state.spf_fails,
        "dkim_fails":   state.dkim_fails,
        "scan_history": state.scan_history[-20:],   # last 20 scans
        "scan_running": state.scan_running,
        "scheduler_running": state.scheduler_running,
        "scheduler_interval": state.scheduler_interval,
    }


# ── Threat log ────────────────────────────────────────────────────────────────
@app.get("/threats", tags=["Monitor"])
def get_threats(limit: int = 100, offset: int = 0):
    """Return paginated list of flagged emails from the database."""
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM flagged_emails ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM flagged_emails").fetchone()[0]

    threats = []
    for row in rows:
        t = dict(row)
        try:
            t["flags"] = json.loads(t.get("flags", "[]"))
        except Exception:
            t["flags"] = []
        threats.append(t)

    return {"total": total, "threats": threats}


@app.delete("/threats", tags=["Monitor"])
def clear_threats():
    """Wipe the flagged_emails table."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM flagged_emails")
        conn.commit()
    state.threats      = 0
    state.scanned      = 0
    state.header_fails = 0
    state.clean        = 0
    state.vt_hits      = 0
    state.spf_fails    = 0
    state.dkim_fails   = 0
    state.scan_history = []
    emit("info", "Threat log cleared by user.")
    return {"status": "cleared"}


@app.get("/threats/{threat_id}", tags=["Monitor"])
def get_threat(threat_id: int):
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM flagged_emails WHERE id = ?", (threat_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Threat not found")
    t = dict(row)
    try:
        t["flags"] = json.loads(t.get("flags", "[]"))
    except Exception:
        t["flags"] = []
    return t


# ── Scan ──────────────────────────────────────────────────────────────────────
@app.post("/scan", tags=["Control"])
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Kick off a scan in a background thread — returns immediately."""
    if state.scan_running:
        return {"status": "already_running"}
    background_tasks.add_task(
        run_scan_thread, req.max_emails, req.folder, req.mode
    )
    return {"status": "started", "mode": req.mode, "max_emails": req.max_emails}


# ── Scheduler ────────────────────────────────────────────────────────────────
@app.post("/scheduler/start", tags=["Control"])
def start_scheduler(req: SchedulerRequest):
    if state.scheduler_running:
        return {"status": "already_running"}
    state._stop_event.clear()
    state.scheduler_interval = req.interval_minutes
    state._scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        args=(req.interval_minutes, state._stop_event),
        daemon=True,
    )
    state._scheduler_thread.start()
    state.scheduler_running = True
    return {"status": "started", "interval_minutes": req.interval_minutes}


@app.post("/scheduler/stop", tags=["Control"])
def stop_scheduler():
    state._stop_event.set()
    state.scheduler_running = False
    return {"status": "stopped"}


@app.get("/scheduler/status", tags=["Control"])
def scheduler_status():
    return {
        "running":            state.scheduler_running,
        "interval_minutes":   state.scheduler_interval,
    }


# ── Settings ──────────────────────────────────────────────────────────────────
@app.get("/settings", tags=["Config"])
def get_settings():
    return {
        "threshold":          state.threshold,
        "enable_spf":         state.enable_spf,
        "enable_dkim":        state.enable_dkim,
        "enable_vt":          state.enable_vt,
        "enable_quarantine":  state.enable_quarantine,
        "enable_alerts":      state.enable_alerts,
    }


@app.post("/settings", tags=["Config"])
def save_settings(req: SettingsRequest):
    state.threshold          = req.threshold
    state.enable_spf         = req.enable_spf
    state.enable_dkim        = req.enable_dkim
    state.enable_vt          = req.enable_vt
    state.enable_quarantine  = req.enable_quarantine
    state.enable_alerts      = req.enable_alerts
    emit("info", f"Settings updated — threshold={req.threshold}")
    return {"status": "saved"}


# ── Config / .env write ───────────────────────────────────────────────────────
@app.post("/config/save", tags=["Config"])
def save_config(req: ConfigRequest):
    """
    Writes credentials to .env in the project directory.
    Passwords are never echoed back — write-only endpoint.
    """
    env_lines = [
        f'EMAIL_ADDRESS="{req.EMAIL_ADDRESS}"',
        f'EMAIL_PASSWORD="{req.EMAIL_PASSWORD}"',
        f'IMAP_SERVER="{req.IMAP_SERVER}"',
        f'IMAP_PORT={req.IMAP_PORT}',
        "",
        f'ALERT_EMAIL="{req.ALERT_EMAIL}"',
        f'SMTP_USER="{req.SMTP_USER}"',
        f'SMTP_PASSWORD="{req.SMTP_PASSWORD}"',
        'SMTP_SERVER="smtp.gmail.com"',
        "SMTP_PORT=587",
        "",
        f'VIRUSTOTAL_API_KEY="{req.VIRUSTOTAL_API_KEY}"',
    ]
    env_path = _here / ".env"
    env_path.write_text("\n".join(env_lines))
    # Reload env vars so the running process picks them up immediately
    load_dotenv(override=True)
    emit("ok", ".env file saved and reloaded.")
    return {"status": "saved", "path": str(env_path)}


# ── Scan history ──────────────────────────────────────────────────────────────
@app.get("/scan-history", tags=["Monitor"])
def scan_history():
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 30"
        ).fetchall()
    return {"history": [dict(r) for r in rows]}


# ─────────────────────────────────────────────────────────────────────────────
#  Accounts  (multi-inbox management)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/accounts", tags=["Accounts"])
def list_accounts():
    """Return all registered accounts (passwords masked)."""
    with state._acct_lock:
        accounts = list(state.accounts)
    safe = []
    for a in accounts:
        s = dict(a)
        s.pop("password", None)   # never return passwords
        safe.append(s)
    return {"accounts": safe}


@app.post("/accounts", tags=["Accounts"])
def add_account(req: AccountAddRequest):
    """Add a new email account to monitor."""
    # Test connection before saving
    from email_handler import connect_to_account
    try:
        mail = connect_to_account({
            "email": req.email, "password": req.password,
            "imap_server": req.imap_server, "imap_port": req.imap_port,
        })
        mail.logout()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Connection test failed: {e}")

    with get_db_connection() as conn:
        try:
            conn.execute(
                """INSERT INTO accounts
                   (label, email, password, imap_server, imap_port, enabled)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (req.label, req.email, req.password,
                 req.imap_server, req.imap_port, int(req.enabled)),
            )
            conn.commit()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Account already exists: {e}")

    _load_accounts_from_db()
    emit("ok", f"Account added: {req.email}")
    return {"status": "added", "email": req.email}


@app.patch("/accounts/{account_id}", tags=["Accounts"])
def update_account(account_id: int, req: AccountUpdateRequest):
    """Update label, enabled flag, or IMAP settings for an account."""
    with get_db_connection() as conn:
        conn.execute(
            """UPDATE accounts
               SET label=?, enabled=?, imap_server=?, imap_port=?
               WHERE id=?""",
            (req.label, int(req.enabled), req.imap_server, req.imap_port, account_id),
        )
        conn.commit()
    _load_accounts_from_db()
    emit("info", f"Account {account_id} updated.")
    return {"status": "updated"}


@app.delete("/accounts/{account_id}", tags=["Accounts"])
def delete_account(account_id: int):
    """Remove an account from monitoring."""
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT email FROM accounts WHERE id=?", (account_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Account not found")
        conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        conn.commit()
    _load_accounts_from_db()
    emit("info", f"Account removed: {row['email']}")
    return {"status": "deleted"}


@app.post("/accounts/{account_id}/test", tags=["Accounts"])
def test_account(account_id: int):
    """Test IMAP connectivity for an account without running a scan."""
    with state._acct_lock:
        acct = next((a for a in state.accounts if a["id"] == account_id), None)
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")
    from email_handler import connect_to_account
    try:
        mail = connect_to_account(acct)
        # Count unread messages
        mail.select("inbox")
        _, data = mail.search(None, "UNSEEN")
        unread = len(data[0].split()) if data[0] else 0
        mail.logout()
        # Save last_scan timestamp
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE accounts SET last_scan=?, last_error='' WHERE id=?",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), account_id),
            )
            conn.commit()
        _load_accounts_from_db()
        return {"status": "ok", "email": acct["email"], "unread": unread}
    except Exception as e:
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE accounts SET last_error=? WHERE id=?",
                (str(e), account_id),
            )
            conn.commit()
        _load_accounts_from_db()
        raise HTTPException(status_code=400, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
#  WebSocket  /ws/logs
# ─────────────────────────────────────────────────────────────────────────────
@app.websocket("/ws/logs")
async def websocket_logs(ws: WebSocket):
    """
    Clients connect here to receive real-time scan log events as JSON:
      { type: "log", level: "ok|info|warn|err", text: "...", ts: "HH:MM:SS" }
    Also forwards named events (threat detected, scan_done) so the dashboard
    can update stats without polling.
    """
    await broadcaster.connect(ws)
    # Send a welcome ping so the client knows the connection is live
    await ws.send_json({"type": "connected", "ts": datetime.now().strftime("%H:%M:%S")})
    try:
        while True:
            # Keep the connection alive; client messages are ignored
            await ws.receive_text()
    except WebSocketDisconnect:
        await broadcaster.disconnect(ws)