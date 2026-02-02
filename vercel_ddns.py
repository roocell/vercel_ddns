#!/usr/bin/env python3
"""
vercel_ddns.py
Dynamic DNS-style updater for Vercel-managed DNS.

- Reads current A records for target names on a domain using Vercel API
- Fetches current public IPv4
- If mismatched, updates (or creates) A records to the new IP

Targets (for roocell.com):
  - "" (root/apex)
  - 3dtest
  - supabase
  - 3d
  - coolify

create .env file with
VERCEL_TOKEN-
VERCEL_TEAM_ID

"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

import requests


VERCEL_API_BASE = "https://api.vercel.com"
DEFAULT_TTL_SECONDS = 60

TARGET_NAMES = ["", "3dtest", "supabase", "3d", "coolify"]


def eprint(*args: Any) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}]", *args, file=sys.stderr)


def getenv_required(key: str) -> str:
    val = os.getenv(key)
    if not val:
        raise SystemExit(f"Missing required env var: {key}")
    return val


def validate_ipv4(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.version != 4:
            raise ValueError("Not IPv4")
        return str(ip)
    except Exception as ex:
        raise SystemExit(f"Invalid IPv4 address '{ip_str}': {ex}")


def http_session(vercel_token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {vercel_token}",
            "Content-Type": "application/json",
        }
    )
    return s


def vercel_get_records(
    s: requests.Session, domain: str, team_id: Optional[str]
) -> List[Dict[str, Any]]:
    """
    GET /v4/domains/{domain}/records  (returns list/paginated records)
    We'll handle either:
      - {"records": [...]}
      - [...] (array)
    """
    url = f"{VERCEL_API_BASE}/v4/domains/{domain}/records"
    params: Dict[str, str] = {}
    if team_id:
        params["teamId"] = team_id

    r = s.get(url, params=params, timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"Vercel list-records failed: {r.status_code} {r.text}")

    data = r.json()
    if isinstance(data, dict) and "records" in data and isinstance(data["records"], list):
        return data["records"]
    if isinstance(data, list):
        return data
    raise SystemExit(f"Unexpected list-records response shape: {json.dumps(data)[:800]}")


def record_is_a(rec: Dict[str, Any]) -> bool:
    # Vercel responses often use recordType for DNS type; type may be "record"/"record-sys"
    rt = (rec.get("recordType") or rec.get("type") or "").upper()
    return rt == "A"


def record_name(rec: Dict[str, Any]) -> str:
    # For Vercel DNS records, "name" is the subdomain label; root is "" (empty string).
    # Some older shapes might use null; normalize to "".
    nm = rec.get("name")
    if nm is None:
        return ""
    return str(nm)


def record_value(rec: Dict[str, Any]) -> str:
    return str(rec.get("value") or "").strip()


def record_id(rec: Dict[str, Any]) -> str:
    rid = rec.get("id") or rec.get("uid")
    if not rid:
        raise ValueError(f"Record missing id/uid: {rec}")
    return str(rid)


def record_ttl(rec: Dict[str, Any]) -> int:
    ttl = rec.get("ttl")
    if isinstance(ttl, int) and ttl >= 60:
        return ttl
    # Some responses use number type; accept if numeric
    if isinstance(ttl, float) and ttl >= 60:
        return int(ttl)
    return DEFAULT_TTL_SECONDS


def get_public_ipv4() -> str:
    """
    Fetch current public IP. Uses multiple providers for robustness.
    """
    providers = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.co/json",
        "https://ipinfo.io/json",
    ]

    last_err = None
    for url in providers:
        try:
            r = requests.get(url, timeout=15, headers={"Accept": "application/json"})
            if r.status_code >= 400:
                last_err = f"{r.status_code} {r.text}"
                continue

            data = r.json()
            ip = data.get("ip") or data.get("address") or data.get("IP")
            if not ip and "ip" in data.get("data", {}):
                ip = data["data"]["ip"]

            if not ip and isinstance(data, dict):
                # Some providers might respond differently; try common keys
                for k in ["ip", "IP", "address"]:
                    if k in data:
                        ip = data[k]
                        break

            if not ip:
                last_err = f"Could not find IP in response from {url}: {data}"
                continue

            return validate_ipv4(str(ip))
        except Exception as ex:
            last_err = str(ex)

    raise SystemExit(f"Failed to determine public IPv4. Last error: {last_err}")


def vercel_update_record(
    s: requests.Session,
    record_id_str: str,
    name: str,
    value: str,
    ttl: int,
    team_id: Optional[str],
    dry_run: bool,
) -> None:
    """
    PATCH /v1/domains/records/{recordId}
    Body supports: name, value, type, ttl, comment, etc.
    """
    url = f"{VERCEL_API_BASE}/v1/domains/records/{record_id_str}"
    params: Dict[str, str] = {}
    if team_id:
        params["teamId"] = team_id

    body = {
        "name": name,
        "type": "A",
        "value": value,
        "ttl": ttl,
        "comment": "auto-updated by vercel_ddns.py",
    }

    if dry_run:
        eprint(f"[dry-run] PATCH {url} params={params} body={body}")
        return

    r = s.patch(url, params=params, data=json.dumps(body), timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"Vercel update-record failed ({name}): {r.status_code} {r.text}")


def vercel_create_record(
    s: requests.Session,
    domain: str,
    name: str,
    value: str,
    ttl: int,
    team_id: Optional[str],
    dry_run: bool,
) -> None:
    """
    POST /v2/domains/{domain}/records
    Body requires: name ("" for root), type, value, ttl
    """
    url = f"{VERCEL_API_BASE}/v2/domains/{domain}/records"
    params: Dict[str, str] = {}
    if team_id:
        params["teamId"] = team_id

    body = {
        "name": name,
        "type": "A",
        "value": value,
        "ttl": ttl,
        "comment": "auto-created by vercel_ddns.py",
    }

    if dry_run:
        eprint(f"[dry-run] POST {url} params={params} body={body}")
        return

    r = s.post(url, params=params, data=json.dumps(body), timeout=30)
    if r.status_code >= 400:
        raise SystemExit(f"Vercel create-record failed ({name}): {r.status_code} {r.text}")


def plan_updates(
    records: List[Dict[str, Any]], desired_ip: str
) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    """
    Returns:
      - map[name] -> record dict (existing A records for targets)
      - names_to_update: targets that exist but value != desired_ip
      - names_to_create: targets missing
    """
    existing: Dict[str, Dict[str, Any]] = {}

    for rec in records:
        if not record_is_a(rec):
            continue
        nm = record_name(rec)
        if nm in TARGET_NAMES:
            existing[nm] = rec

    names_to_update: List[str] = []
    names_to_create: List[str] = []

    for nm in TARGET_NAMES:
        if nm not in existing:
            names_to_create.append(nm)
            continue
        current_val = record_value(existing[nm])
        if current_val != desired_ip:
            names_to_update.append(nm)

    return existing, names_to_update, names_to_create


def run_once(domain: str, interval: int, dry_run: bool, verbose: bool) -> bool:
    """
    Returns True if any changes were applied (or would be applied in dry-run).
    """
    vercel_token = getenv_required("VERCEL_TOKEN")
    team_id = os.getenv("VERCEL_TEAM_ID")

    s = http_session(vercel_token)

    public_ip = get_public_ipv4()
    records = vercel_get_records(s, domain, team_id)

    existing, to_update, to_create = plan_updates(records, public_ip)

    # "use vercel APIs to check the current public IP for roocell.com"
    # We'll show what Vercel currently has for each target.
    if verbose:
        eprint(f"Public IPv4: {public_ip}")
        for nm in TARGET_NAMES:
            if nm in existing:
                eprint(f"Vercel A {domain} [{nm or '(root)'}] = {record_value(existing[nm])}")
            else:
                eprint(f"Vercel A {domain} [{nm or '(root)'}] = (missing)")

    if not to_update and not to_create:
        if verbose:
            eprint("No changes needed.")
        return False

    if verbose:
        if to_update:
            eprint("Will update:", ", ".join([n or "(root)" for n in to_update]))
        if to_create:
            eprint("Will create:", ", ".join([n or "(root)" for n in to_create]))

    # Apply creates first (so everything exists)
    for nm in to_create:
        vercel_create_record(
            s=s,
            domain=domain,
            name=nm,
            value=public_ip,
            ttl=DEFAULT_TTL_SECONDS,
            team_id=team_id,
            dry_run=dry_run,
        )

    # Apply updates
    for nm in to_update:
        rec = existing[nm]
        ttl = record_ttl(rec)
        rid = record_id(rec)
        vercel_update_record(
            s=s,
            record_id_str=rid,
            name=nm,
            value=public_ip,
            ttl=ttl,
            team_id=team_id,
            dry_run=dry_run,
        )

    return True


def main() -> None:
    p = argparse.ArgumentParser(description="Dynamic DNS updater for Vercel DNS")
    p.add_argument("--domain", default="roocell.com", help="Domain to manage (default: roocell.com)")
    p.add_argument("--interval", type=int, default=300, help="Polling interval seconds (default: 300)")
    p.add_argument("--once", action="store_true", help="Run once and exit (recommended for cron)")
    p.add_argument("--dry-run", action="store_true", help="Print what would change, don’t call PATCH/POST")
    p.add_argument("--verbose", action="store_true", help="More logging")
    load_dotenv()

    args = p.parse_args()

    if args.interval < 30 and not args.once:
        raise SystemExit("--interval too small; use >= 30 seconds to avoid rate issues")

    if args.once:
        changed = run_once(args.domain, args.interval, args.dry_run, args.verbose)
        print("changed" if changed else "no-change")
        return

    # Monitor loop
    last_public_ip: Optional[str] = None
    while True:
        try:
            # Fast path: if public IP hasn't changed since last time, we can skip some work.
            current_ip = get_public_ipv4()
            if last_public_ip == current_ip:
                if args.verbose:
                    eprint(f"No public IP change ({current_ip}). Sleeping {args.interval}s...")
                time.sleep(args.interval)
                continue

            # Public IP changed (or first run): compare against Vercel and update if needed
            changed = run_once(args.domain, args.interval, args.dry_run, args.verbose)
            last_public_ip = current_ip

            if args.verbose:
                eprint(f"{'Updated' if changed else 'No Vercel changes needed'}. Sleeping {args.interval}s...")
            time.sleep(args.interval)

        except KeyboardInterrupt:
            eprint("Exiting.")
            return
        except Exception as ex:
            eprint(f"Error: {ex}")
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
