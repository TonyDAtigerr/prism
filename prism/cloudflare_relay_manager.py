#!/usr/bin/env python3
"""
cloudflare_relay_manager.py
-----------------------------
Provisioning tool that stands in for `cloud-proxy` from the original
AWS-based write-up. Instead of launching EC2 instances and SSHing in to
start SOCKS proxies, this deploys N copies of worker.js as Cloudflare
Workers via the Cloudflare REST API, and writes their URLs to
endpoints.json for rotator_addon.py to consume.

Setup:
    pip install -r requirements.txt

    Create prism.json (do NOT commit this file):
    {
      "api_token": "<Cloudflare API token, 'Edit Cloudflare Workers' template>",
      "account_id": "<Cloudflare account ID>",
      "auth_token": "<long random secret shared with worker.js>",
      "relay_prefix": "<optional -- name every deployed relay starts with;
                         a random one is generated if omitted>",

      // The rest are optional rotator_addon.py knobs -- all off/default
      // unless set. See that file's header for the full explanation.
      "sticky_seconds": 300,      // same relay+UA per (client, target host)
      "pacing_min_seconds": 0,    // random delay before each request...
      "pacing_max_seconds": 0,    // ...between these two (0/0 = off)
      "burn_after_requests": 0,   // redeploy a relay after N uses (0 = off)
      "burn_after_seconds": 0     // ...or after this long in the pool
    }

Usage:
    python3 cloudflare_relay_manager.py create --count 6
    python3 cloudflare_relay_manager.py list
    python3 cloudflare_relay_manager.py test
    python3 cloudflare_relay_manager.py cleanup

Notes:
    - Cloudflare's Workers upload API (multipart metadata format, subdomain
      enable endpoint) has changed shape before and can change again -- if
      `create` fails with an unexpected response, check
      https://developers.cloudflare.com/api/resources/workers/ before
      assuming this script is wrong.
    - This intentionally mirrors the public "FlareProx" pattern
      (https://github.com/MrTurvey/flareprox) and the HackTricks writeup on
      Cloudflare Worker pass-through proxies -- this is a known, documented
      red-team technique, not something novel being hidden here.
"""

import argparse
import json
import sys
from pathlib import Path

import requests

from prism.relay_common import (  # noqa: F401 -- re-exported for existing `cfm.X` callers
    CONFIG_PATH,
    ENDPOINTS_PATH,
    load_config,
    load_endpoints,
    name_prefix,
    random_suffix,
    save_endpoints,
    cmd_test,
    warn_if_wrong_backend,
)

WORKER_JS_PATH = Path(__file__).resolve().parent / "worker.js"
API_BASE = "https://api.cloudflare.com/client/v4"


def load_worker_source(auth_token):
    if not WORKER_JS_PATH.exists():
        sys.exit(f"Missing {WORKER_JS_PATH} next to this script.")
    src = WORKER_JS_PATH.read_text()
    # Bake the shared secret into the fallback constant for scripts deployed
    # via this raw-API path (wrangler secrets aren't settable through this
    # simple multipart upload). Treat the deployed copy as sensitive.
    return src.replace("CHANGE_ME_TO_A_LONG_RANDOM_SECRET", auth_token)


def headers(cfg):
    return {"Authorization": f"Bearer {cfg['api_token']}"}


def get_workers_dev_subdomain(cfg):
    """Look up the account's *.workers.dev subdomain (must exist already;
    create one in the dashboard under Workers & Pages if this returns empty)."""
    resp = requests.get(
        f"{API_BASE}/accounts/{cfg['account_id']}/workers/subdomain",
        headers=headers(cfg),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    subdomain = (data.get("result") or {}).get("subdomain")
    if not subdomain:
        sys.exit(
            "No workers.dev subdomain configured on this account yet. "
            "Set one up once in the Cloudflare dashboard (Workers & Pages "
            "-> Overview) then re-run."
        )
    return subdomain


def deploy_one(cfg, script_name, worker_source):
    metadata = {
        "main_module": "worker.js",
        "compatibility_date": "2026-08-01",
    }
    files = {
        "metadata": (None, json.dumps(metadata), "application/json"),
        "worker.js": (
            "worker.js",
            worker_source,
            "application/javascript+module",
        ),
    }
    resp = requests.put(
        f"{API_BASE}/accounts/{cfg['account_id']}/workers/scripts/{script_name}",
        headers=headers(cfg),
        files=files,
        timeout=60,
    )
    if not resp.ok:
        print(f"[!] Deploy failed for {script_name}: {resp.status_code} {resp.text}")
        return False

    # Enable the free default *.workers.dev route so the script is publicly
    # reachable (no custom domain involved). Cloudflare's API moved this
    # from PUT to POST at some point -- PUT now fails with a 10405 "Method
    # not allowed for this authentication scheme" error that has nothing to
    # do with actual permissions. See developers.cloudflare.com/api/resources/
    # workers/subresources/scripts/subresources/subdomain/ if it changes again.
    sub_resp = requests.post(
        f"{API_BASE}/accounts/{cfg['account_id']}/workers/scripts/{script_name}/subdomain",
        headers=headers(cfg),
        json={"enabled": True, "previews_enabled": False},
        timeout=30,
    )
    if not sub_resp.ok:
        print(
            f"[!] Script {script_name} deployed but enabling workers.dev "
            f"route failed: {sub_resp.status_code} {sub_resp.text}"
        )
        return False
    return True


def deploy_one_relay(cfg, name):
    """Uniform interface every backend exposes (gcp_relay_manager.py and
    azure_relay_manager.py have the same-shaped deploy_one already; this
    just wraps Cloudflare's two-step deploy_one()+subdomain lookup to
    match). Returns the relay's URL on success, None on failure. Used by
    both cmd_create (bulk deploy) and rotator_addon.py's burn policy
    (single on-demand replacement)."""
    subdomain = get_workers_dev_subdomain(cfg)
    worker_source = load_worker_source(cfg["auth_token"])
    if not deploy_one(cfg, name, worker_source):
        return None
    return f"https://{name}.{subdomain}.workers.dev"


def cmd_create(cfg, count):
    existing = load_endpoints()
    created = []
    for _ in range(count):
        name = f"{name_prefix(cfg)}-{random_suffix()}"
        print(f"[*] Deploying {name} ...")
        url = deploy_one_relay(cfg, name)
        if url:
            created.append({"name": name, "url": url, "provider": "cloudflare"})
            print(f"    -> {url}")
        else:
            print("    -> failed, skipping")
    all_endpoints = existing + created
    save_endpoints(all_endpoints)
    print(f"\n[+] {len(created)} endpoint(s) created, {len(all_endpoints)} total in {ENDPOINTS_PATH}")


def _our_scripts(cfg):
    """Scripts on this account that belong to us: anything endpoints.json is
    tracking by exact name (survives a relay_prefix change), plus anything
    matching the *current* prefix that isn't tracked locally (e.g. deployed
    manually, or endpoints.json got deleted)."""
    resp = requests.get(
        f"{API_BASE}/accounts/{cfg['account_id']}/workers/scripts",
        headers=headers(cfg),
        timeout=30,
    )
    resp.raise_for_status()
    all_names = {s["id"] for s in resp.json().get("result", [])}
    tracked = set()
    if ENDPOINTS_PATH.exists():
        tracked = {ep["name"] for ep in json.loads(ENDPOINTS_PATH.read_text())}
    prefix = name_prefix(cfg)
    return sorted((tracked | {n for n in all_names if n.startswith(prefix)}) & all_names)


def cmd_list(cfg):
    scripts = _our_scripts(cfg)
    if not scripts:
        print("There are currently no deployed Cloudflare Workers.")
        return
    for s in scripts:
        print(s)


def delete_one(cfg, script_name):
    """Delete a single relay Worker by name. Returns True on success."""
    d = requests.delete(
        f"{API_BASE}/accounts/{cfg['account_id']}/workers/scripts/{script_name}",
        headers=headers(cfg),
        timeout=30,
    )
    return d.ok


def cmd_cleanup(cfg):
    scripts = _our_scripts(cfg)
    if not scripts:
        print("There are currently no deployed Cloudflare Workers.")
    for name in scripts:
        status = "deleted" if delete_one(cfg, name) else "FAILED"
        print(f"{name}: {status}")
    if ENDPOINTS_PATH.exists():
        ENDPOINTS_PATH.unlink()
        print(f"Removed {ENDPOINTS_PATH}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Deploy N new relay Workers")
    p_create.add_argument("--count", type=int, default=3)

    sub.add_parser("list", help="List relay Workers on this account")
    sub.add_parser("test", help="Send a canary request through every endpoint")
    sub.add_parser("cleanup", help="Delete every relay Worker on this account")

    args = parser.parse_args()
    cfg = load_config()
    warn_if_wrong_backend(cfg, "cloudflare")

    if args.command == "create":
        cmd_create(cfg, args.count)
    elif args.command == "list":
        cmd_list(cfg)
    elif args.command == "test":
        cmd_test(cfg)
    elif args.command == "cleanup":
        cmd_cleanup(cfg)


if __name__ == "__main__":
    main()
