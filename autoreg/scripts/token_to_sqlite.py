#!/usr/bin/env python3
"""Adapter: autoreg JSON token → Kiro-gateway SQLite credential.

Autoreg (leoleo166) writes tokens as
    ~/.kiro-batch-login/tokens/token-BuilderId-IdC-<name>-<ts>.json

with camelCase keys:
    {"accessToken", "refreshToken", "expiresAt", "_clientId",
     "_clientSecret", "region", "accountName", ...}

Our Kiro-gateway container (kirocli/kiro-gateway) reads SQLite files
whose schema matches what kiro-cli / kiro-desktop writes. Checked
against an existing working acc*.sqlite3: it needs an `auth_kv`
key-value table with two entries:

  key: 'kirocli:odic:token'
  val: JSON with snake_case fields
       {access_token, refresh_token, expires_at, region, scopes, provider}

  key: 'kirocli:odic:device-registration'
  val: JSON
       {client_id, client_secret, region}

Plus the other tables (migrations/state/history/conversations*) which
we copy from a known-good template — their presence is required by
the SQLite migrations the gateway runs on startup.

Usage:
    token_to_sqlite.py <input.json> <output.sqlite3> [--template /path/acc7.sqlite3]

On success: writes <output.sqlite3> with the converted token,
prints the target path, exits 0.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from pathlib import Path


DEFAULT_TEMPLATE = Path("/home/user1/workspace/kiro-gateway/credentials/acc7.sqlite3")


def convert_token(autoreg_json: dict) -> tuple[dict, dict]:
    """Return (token_row, registration_row) with snake_case fields."""
    def take(*keys, default=None):
        for k in keys:
            if k in autoreg_json and autoreg_json[k] is not None:
                return autoreg_json[k]
        return default

    token_row = {
        "access_token": take("accessToken", "access_token"),
        "refresh_token": take("refreshToken", "refresh_token"),
        "expires_at": take("expiresAt", "expires_at"),
        "region": take("region", default="us-east-1"),
        "provider": take("provider", default="BuilderId"),
    }
    if "scopes" in autoreg_json:
        token_row["scopes"] = autoreg_json["scopes"]
    # profile_arn is optional; gateway works without it for most chat calls
    if "profileArn" in autoreg_json or "profile_arn" in autoreg_json:
        token_row["profile_arn"] = take("profileArn", "profile_arn")

    registration_row = {
        "client_id": take("_clientId", "client_id"),
        "client_secret": take("_clientSecret", "client_secret"),
        "region": take("region", default="us-east-1"),
    }
    return token_row, registration_row


def _require_fields(row: dict, fields: tuple[str, ...], label: str) -> None:
    missing = [f for f in fields if not row.get(f)]
    if missing:
        raise ValueError(f"{label} missing fields: {missing}")


def write_sqlite(
    output_path: Path,
    token_row: dict,
    registration_row: dict,
    template_path: Path,
) -> None:
    if not template_path.exists():
        raise FileNotFoundError(f"template SQLite not found: {template_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Copy template to inherit schema + other tables the gateway needs.
    shutil.copyfile(template_path, output_path)

    conn = sqlite3.connect(str(output_path))
    try:
        cur = conn.cursor()
        # Replace the token row atomically — INSERT OR REPLACE relies on
        # the PRIMARY KEY on auth_kv.key (verified in the template schema).
        cur.execute(
            "INSERT OR REPLACE INTO auth_kv (key, value) VALUES (?, ?)",
            ("kirocli:odic:token", json.dumps(token_row)),
        )
        if registration_row.get("client_id") and registration_row.get("client_secret"):
            cur.execute(
                "INSERT OR REPLACE INTO auth_kv (key, value) VALUES (?, ?)",
                (
                    "kirocli:odic:device-registration",
                    json.dumps(registration_row),
                ),
            )
        # Template may carry a stale social token from acc7; wipe it so
        # the gateway resolves our OIDC token first by key priority.
        cur.execute("DELETE FROM auth_kv WHERE key = 'kirocli:social:token'")
        # Also wipe any state-table cached profile so the gateway doesn't
        # reuse acc7's profile_arn for the new account.
        cur.execute("DELETE FROM state WHERE key = 'api.codewhisperer.profile'")
        conn.commit()
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="path to token-BuilderId-IdC-*.json")
    ap.add_argument("output", help="target .sqlite3 path")
    ap.add_argument(
        "--template",
        default=str(DEFAULT_TEMPLATE),
        help=f"template .sqlite3 to inherit schema from (default: {DEFAULT_TEMPLATE})",
    )
    args = ap.parse_args()

    in_path = Path(args.input).expanduser().resolve()
    out_path = Path(args.output).expanduser().resolve()
    tpl_path = Path(args.template).expanduser().resolve()

    data = json.loads(in_path.read_text(encoding="utf-8"))
    token_row, registration_row = convert_token(data)
    _require_fields(token_row, ("access_token",), "token")
    # refresh_token optional: when step 12f (OIDC device auth) fails we
    # still get a usable accessToken from step 12 ExchangeToken. The
    # gateway can serve that account until the token expires (~1 hour)
    # even without refresh — better to install it and burn for an hour
    # than to throw away a working credential.

    write_sqlite(out_path, token_row, registration_row, tpl_path)
    print(f"Wrote {out_path}")
    print(f"  account: {data.get('accountName') or data.get('email') or '(unknown)'}")
    print(f"  provider: {token_row['provider']}")
    print(f"  expires_at: {token_row['expires_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
