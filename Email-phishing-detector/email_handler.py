"""
email_handler.py — multi-account IMAP support

Single-account usage (backward-compatible):
    from email_handler import connect_to_email, fetch_emails
    mail = connect_to_email()
    emails = fetch_emails(mail)

Multi-account usage:
    from email_handler import connect_to_account, fetch_emails_from_all
    results = fetch_emails_from_all(accounts)
    # results = [ {account, mail, emails: [...]} , ... ]
"""

import email
import imaplib
import os
import re
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

# ── Default single-account credentials (from .env) ───────────────────────────
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
IMAP_SERVER   = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT     = int(os.getenv("IMAP_PORT", 993))


# ─────────────────────────────────────────────────────────────────────────────
#  Single-account helpers  (original API — still works exactly as before)
# ─────────────────────────────────────────────────────────────────────────────

def connect_to_email():
    """Connect using the default .env credentials. Returns an IMAP4_SSL object."""
    return connect_to_account({
        "email":       EMAIL_ADDRESS,
        "password":    EMAIL_PASSWORD,
        "imap_server": IMAP_SERVER,
        "imap_port":   IMAP_PORT,
    })


def fetch_emails(mail, folder: str = "inbox", max_emails: int = 50):
    """Fetch unread emails from a single connected mailbox."""
    return _fetch_from_connection(mail, folder=folder, max_emails=max_emails)


# ─────────────────────────────────────────────────────────────────────────────
#  Multi-account helpers  (new)
# ─────────────────────────────────────────────────────────────────────────────

def connect_to_account(account: dict) -> imaplib.IMAP4_SSL:
    """
    Connect to a single account dict:
      { email, password, imap_server, imap_port, label (optional) }
    Returns an open IMAP4_SSL connection.
    Raises RuntimeError on failure (caller should catch and log, not crash).
    """
    addr   = account.get("email", "")
    passwd = account.get("password", "")
    server = account.get("imap_server", "imap.gmail.com")
    port   = int(account.get("imap_port", 993))

    if not addr:
        raise ValueError(f"Account has no email address.")
    if not passwd:
        raise ValueError(f"Account {addr!r} has no password.")

    try:
        mail = imaplib.IMAP4_SSL(server, port)
    except Exception as e:
        raise RuntimeError(f"[{addr}] Cannot reach {server}:{port} — {e}")

    try:
        mail.login(addr, passwd)
        print(f"✅ IMAP login OK — {addr}")
        return mail
    except imaplib.IMAP4.error as e:
        raise RuntimeError(
            f"[{addr}] Login failed: {e}. "
            "For Gmail use an App Password (Google Account → Security → App Passwords)."
        )


def fetch_emails_from_all(
    accounts: list[dict],
    folder:     str = "inbox",
    max_emails: int = 50,
) -> list[dict]:
    """
    Connect to every account in `accounts`, fetch unread emails from each,
    tag every email with the account address, and return a flat list.

    Each returned email dict has an extra key:
        account  — the email address of the inbox it came from
        mail_obj — the open IMAP connection (needed for quarantine)

    Accounts that fail to connect are skipped; errors are printed but do not
    stop the other accounts from being scanned.

    `accounts` is a list of dicts:
      [
        { "email": "a@gmail.com", "password": "...", "imap_server": "imap.gmail.com",
          "imap_port": 993, "label": "Work", "enabled": True },
        ...
      ]
    """
    all_emails: list[dict] = []

    for acct in accounts:
        if not acct.get("enabled", True):
            print(f"⏭  Skipping disabled account: {acct.get('email','?')}")
            continue

        addr = acct.get("email", "unknown")
        try:
            mail = connect_to_account(acct)
        except (ValueError, RuntimeError) as e:
            print(f"❌ [{addr}] Connection failed: {e}")
            continue

        try:
            emails = _fetch_from_connection(mail, folder=folder, max_emails=max_emails)
        except Exception as e:
            print(f"❌ [{addr}] Fetch failed: {e}")
            try:
                mail.logout()
            except Exception:
                pass
            continue

        # Tag each email with the source account and keep the connection open
        # so quarantine.py can move the message later.
        for em in emails:
            em["account"]  = addr
            em["mail_obj"] = mail   # quarantine needs this

        print(f"📨 [{addr}] {len(emails)} unread email(s).")
        all_emails.extend(emails)

    print(f"📬 Total across all accounts: {len(all_emails)} email(s).")
    return all_emails


# ─────────────────────────────────────────────────────────────────────────────
#  Internal fetch logic  (shared by both single and multi-account paths)
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_from_connection(
    mail,
    folder:     str = "inbox",
    max_emails: int = 50,
) -> list[dict]:
    """Pull unread emails from an already-connected IMAP session."""
    if mail is None:
        print("⚠️  No IMAP connection provided.")
        return []

    try:
        mail.select(folder)
    except Exception as e:
        print(f"⚠️  Could not select folder '{folder}': {e}")
        return []

    result, data = mail.search(None, "UNSEEN")
    if result != "OK":
        print("⚠️  UNSEEN search failed.")
        return []

    email_ids = data[0].split()
    if not email_ids:
        return []

    # Respect max_emails cap — take the most recent ones
    email_ids = email_ids[-max_emails:]

    emails: list[dict] = []

    for email_id in email_ids:
        result, msg_data = mail.fetch(email_id, "(RFC822)")
        if result != "OK":
            continue

        raw_bytes = msg_data[0][1]
        msg       = email.message_from_bytes(raw_bytes)

        # ── Plain-text body ───────────────────────────────────────────────────
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    body    = payload.decode(errors="ignore") if payload else ""
                    break
        else:
            payload = msg.get_payload(decode=True)
            body    = payload.decode(errors="ignore") if payload else ""

        # ── Sender IP from Received header (for SPF) ─────────────────────────
        sender_ip: Optional[str] = None
        received  = msg.get("Received", "")
        ip_match  = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', received)
        if ip_match:
            sender_ip = ip_match.group(1)

        emails.append({
            "id":        email_id.decode(),
            "from":      msg.get("From", ""),
            "subject":   msg.get("Subject", ""),
            "body":      body,
            "raw_bytes": raw_bytes,
            "sender_ip": sender_ip,
            # 'account' and 'mail_obj' are injected by fetch_emails_from_all()
        })

    return emails