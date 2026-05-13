#!/usr/bin/env python3
"""Pure-protocol Kiro autoreg runner.

Ported from lxf746/any-auto-register (platforms/kiro/core.py).

Instead of driving a headless browser (which AWS detects via
navigator.webdriver leaks, WebGL fingerprint, etc.), this script
replays the raw HTTP protocol AWS Builder ID uses during signup:

  1. /platform/{DIR}/api/execute (signin flow)
  2. /platform/{DIR}/api/execute (signup flow)
  3. profile.aws.amazon.com TES token
  4. profile start page
  5. send OTP to email
  6. IMAP poll for 6-digit code
  7. create identity (submit OTP)
  8. signup registration
  9. set password
  10. final login → accessToken + sessionToken
  11. oidc/client/register + device_authorization → clientId + clientSecret + refreshToken

Uses curl_cffi with impersonate='chrome131' to produce a Chrome-like
TLS/HTTP2 fingerprint, bypassing headless-browser detection entirely.

Usage:
    source .venv/bin/activate
    set -a; source .env; set +a
    python3 scripts/protocol_register.py [--email user+alias@gmail.com]

On success:
    1. writes JSON token to ~/.kiro-batch-login/tokens/<timestamped>.json
    2. feeds it to scripts/install-token.sh → kiro-gateway-v2 restart
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


def _imap_otp_callback(target_email: str, timeout: int = 180, poll: int = 3):
    """Build an otp_callback that polls the IMAP user (root mailbox,
    catches plus-aliased mail that Gmail delivers to the base address)
    and returns the first 6-digit code from an AWS / signin.aws email
    that was sent to *target_email* in the last `timeout` seconds."""
    host = os.environ["IMAP_SERVER"]
    port = int(os.environ.get("IMAP_PORT", "993"))
    user = os.environ["IMAP_USER"]
    pwd  = os.environ["IMAP_PASSWORD"]

    def _connect():
        m = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
        m.login(user, pwd)
        m.select("INBOX")
        return m

    def _find() -> str | None:
        start = time.time()
        seen: set[bytes] = set()
        target_lc = target_email.lower()
        is_ddg = target_lc.endswith("@duck.com")
        while time.time() - start < timeout:
            try:
                m = _connect()
                # When the target is a duck.com alias, AWS sends to <alias>@duck.com
                # and DDG forwards to our gmail inbox, rewriting From/To. Original
                # alias survives in the *body* and is also exposed in *Reply-To* /
                # *From* (DDG embeds "<original-sender>_at_signin.aws_<hash>@duck.com"
                # and "<alias>" appears verbatim in the forwarded body footer).
                if is_ddg:
                    search_q = '(FROM "duck.com" SINCE "%s")' % datetime.utcnow().strftime('%d-%b-%Y')
                else:
                    search_q = '(FROM "no-reply@signin.aws" SINCE "%s")' % datetime.utcnow().strftime('%d-%b-%Y')
                typ, data = m.search(None, search_q)
                ids = data[0].split() if data and data[0] else []
                for mid in reversed(ids):
                    if mid in seen:
                        continue
                    seen.add(mid)
                    typ, raw = m.fetch(mid, "(RFC822)")
                    if not raw or not raw[0]:
                        continue
                    msg = message_from_bytes(raw[0][1])
                    # Build body once (we need it both for filter check and OTP extract)
                    body_chunks: list[str] = []
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() in ("text/plain", "text/html"):
                                try:
                                    body_chunks.append(part.get_payload(decode=True).decode("utf-8", "replace"))
                                except Exception:
                                    pass
                    else:
                        try:
                            body_chunks.append(msg.get_payload(decode=True).decode("utf-8", "replace"))
                        except Exception:
                            body_chunks.append(msg.get_payload() or "")
                    combined = "\n".join(body_chunks)

                    if is_ddg:
                        # DDG forwards: must originate from signin.aws and target alias must appear
                        from_hdr = (msg.get("From") or "").lower()
                        reply_to = (msg.get("Reply-To") or "").lower()
                        subject_hdr = (msg.get("Subject") or "").lower()
                        if "signin.aws" not in (from_hdr + reply_to + combined.lower()):
                            continue
                        # Match alias in body, headers, or subject (DDG places it in multiple spots)
                        alias_local = target_lc.split("@", 1)[0]
                        if target_lc not in combined.lower() and \
                           target_lc not in from_hdr and \
                           target_lc not in reply_to and \
                           alias_local not in subject_hdr and \
                           alias_local not in from_hdr:
                            continue
                    else:
                        to_hdr = (msg.get("To") or "").lower()
                        delivered_to = (msg.get("Delivered-To") or "").lower()
                        if target_lc not in to_hdr and target_lc not in delivered_to:
                            continue

                    for pat in [
                        r"verification code is[:\s]*(\d{6})",
                        r"code[:\s]*(\d{6})",
                        r"\b(\d{6})\b",
                    ]:
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
    """Write result as Kiro Desktop-compatible JSON, then install via pipeline."""
    tokens_dir = Path.home() / ".kiro-batch-login" / "tokens"
    tokens_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", result.get("email", "acc").split("@")[0])
    ts = int(time.time() * 1000)
    fname = f"token-BuilderId-IdC-{safe_name}-{ts}.json"
    path = tokens_dir / fname

    # Autoreg pipeline expects accessToken/refreshToken/expiresAt camelCase.
    # core.py already returns tokens in camelCase — just add expiresAt.
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


def run_one(email: str | None = None, proxy: str | None = None) -> dict | None:
    from kiro_protocol.protocol_mailbox import KiroProtocolMailboxWorker

    if not email:
        # Generate from our existing EmailGenerator (plus_alias strategy).
        from core.email_generator import EmailGenerator
        g = EmailGenerator.from_env()
        r = g.generate()
        email = r.registration_email
        name = r.display_name
    else:
        name = "Kiro User"

    print(f"[RUN] email={email!r} name={name!r}")

    worker = KiroProtocolMailboxWorker(proxy=proxy, tag="PROTO", log_fn=print)
    otp_cb = _imap_otp_callback(email, timeout=240)

    result = worker.run(
        email=email,
        password=None,  # auto-generate in worker
        name=name,
        mail_token=None,
        otp_timeout=240,
        otp_callback=otp_cb,
    )
    if not result or not result.get("accessToken"):
        print(f"[RUN] failed: {result!r}")
        return None

    token_path = _save_builder_id_token(result)
    _install_into_gateway(token_path)
    return result


def main() -> int:
    _load_env()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--email", default=None, help="use explicit email (default: generate via plus_alias)")
    ap.add_argument("--proxy", default=os.environ.get("BROWSER_PROXY"), help="HTTP/SOCKS5 proxy (default: $BROWSER_PROXY)")
    args = ap.parse_args()

    try:
        r = run_one(email=args.email, proxy=args.proxy)
    except Exception as e:
        print(f"[FATAL] {type(e).__name__}: {e}")
        return 1
    return 0 if r else 2


if __name__ == "__main__":
    sys.exit(main())
