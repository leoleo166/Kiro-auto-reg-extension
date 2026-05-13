#!/usr/bin/env python3
"""Browser-based Kiro autoreg runner (Camoufox / Firefox-stealth).

Mirrors scripts/protocol_register.py but drives a real browser via
camoufox.sync_api.Camoufox instead of curl_cffi.

Use when AWS fraud detection bans pure-protocol registrations
(seen 2026-05-13: every account created via curl_cffi gets a
"Response Required: Your Kiro Account" email 1-2 min later, even
with realistic FWCIM, humanlike sleeps, chrome146 impersonation,
and short numeric +alias).

Usage:
    source .venv/bin/activate
    set -a; source .env; set +a
    python3 scripts/browser_register.py [--email user+alias@gmail.com] [--no-headless]
"""

from __future__ import annotations

import argparse
import imaplib
import json
import os
import re
import ssl
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _load_env() -> None:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env", override=False)


def _imap_otp_callback(target_email: str, timeout: int = 240, poll: int = 3):
    host = os.environ["IMAP_SERVER"]
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ["IMAP_USER"]
    pwd = os.environ["IMAP_PASSWORD"]

    def _connect():
        m = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
        m.login(user, pwd)
        m.select("INBOX")
        return m

    def _find() -> str | None:
        start = time.time()
        seen: set[bytes] = set()
        target_lc = target_email.lower()
        while time.time() - start < timeout:
            try:
                m = _connect()
                since = (datetime.utcnow() - timedelta(minutes=5)).strftime("%d-%b-%Y")
                typ, data = m.search(None, f"SINCE {since}")
                for mid in data[0].split():
                    if mid in seen:
                        continue
                    seen.add(mid)
                    typ, msg = m.fetch(mid, "(RFC822)")
                    raw = msg[0][1]
                    parsed = message_from_bytes(raw)
                    to = (parsed.get("To") or "").lower()
                    delivered_to = (parsed.get("Delivered-To") or "").lower()
                    if target_lc not in to and target_lc not in delivered_to:
                        continue
                    body_text = ""
                    if parsed.is_multipart():
                        for part in parsed.walk():
                            if part.get_content_type() in ("text/plain", "text/html"):
                                try:
                                    body_text += part.get_payload(decode=True).decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                    else:
                        try:
                            body_text = parsed.get_payload(decode=True).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                    combined = f"{parsed.get('Subject','')}\n{body_text}"
                    for pat in (r"verification code is[^\d]*?(\d{6})",
                                r"\b(\d{6})\b"):
                        mm = re.search(pat, combined, re.IGNORECASE)
                        if mm:
                            print(f"[OTP] extracted code {mm.group(1)} from message id {mid!r}")
                            m.logout()
                            return mm.group(1)
                m.logout()
            except Exception as e:
                print(f"[OTP] poll error: {e}")
            time.sleep(poll)
        return None

    return _find


def _save_builder_id_token(result: dict) -> Path:
    tokens_dir = Path.home() / ".kiro-batch-login" / "tokens"
    tokens_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", result.get("email", "acc").split("@")[0])
    ts = int(time.time() * 1000)
    fname = f"token-BuilderId-IdC-{safe_name}-{ts}.json"
    path = tokens_dir / fname

    expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat().replace("+00:00", "Z")

    out = {
        "accessToken": result.get("accessToken", ""),
        "refreshToken": result.get("refreshToken", ""),
        "expiresAt": expires_at,
        "tokenType": "Bearer",
        "accountName": result.get("email", ""),
        "provider": "BuilderId",
        "authMethod": "DeviceFlow",
        "region": "us-east-1",
        "createdAt": datetime.now().isoformat(),
        "_clientId": result.get("clientId", ""),
        "_clientSecret": result.get("clientSecret", ""),
        "password": result.get("password", ""),
        "sessionToken": result.get("sessionToken", ""),
    }
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"[SAVE] token written: {path}")
    return path


def _install_into_gateway(token_path: Path) -> int:
    installer = REPO_ROOT / "scripts" / "install-token.sh"
    if not installer.exists():
        print(f"[INSTALL] skipped — {installer} not found")
        return 0
    print(f"[INSTALL] {installer} {token_path}")
    r = subprocess.run(["bash", str(installer), str(token_path)], capture_output=False)
    return r.returncode


def run_one(email: str | None = None, proxy: str | None = None, headless: bool = True) -> dict | None:
    from kiro_protocol.browser_register import KiroBrowserRegister

    if not email:
        from core.email_generator import EmailGenerator
        g = EmailGenerator.from_env()
        r = g.generate()
        email = r.registration_email

    print(f"[RUN] email={email!r} headless={headless} proxy={proxy}")

    otp_cb = _imap_otp_callback(email, timeout=300)

    runner = KiroBrowserRegister(
        headless=headless,
        proxy=proxy,
        otp_callback=otp_cb,
        log_fn=print,
    )
    result = runner.run(email=email, password="")
    if not result or not result.get("accessToken"):
        print(f"[RUN] failed: {result!r}")
        return None

    token_path = _save_builder_id_token(result)
    _install_into_gateway(token_path)
    return result


def main():
    _load_env()
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", default=None)
    ap.add_argument("--proxy", default=os.environ.get("BROWSER_PROXY"))
    ap.add_argument("--no-headless", action="store_true", help="Show the Camoufox window (requires Xvfb / DISPLAY)")
    args = ap.parse_args()

    try:
        r = run_one(email=args.email, proxy=args.proxy, headless=not args.no_headless)
    except KeyboardInterrupt:
        print("interrupted")
        return 130
    return 0 if r and r.get("accessToken") else 1


if __name__ == "__main__":
    raise SystemExit(main())
