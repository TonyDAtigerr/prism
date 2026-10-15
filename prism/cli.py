#!/usr/bin/env python3
"""
prism
--------
Single entrypoint for the whole rotating-proxy workflow: create config,
deploy N relay endpoints, start the local mitmproxy rotator, and tear
everything down again -- one command instead of chaining the manual steps
by hand.

Pick a provider -- Cloudflare Workers, GCP Cloud Functions, or Azure
Functions. All three deploy the same relay and behave identically from
there, so the choice comes down to deploy speed and the leak note below.
README.md has the setup walkthrough for each.

DISCLAIMER: HTTP(S) traffic only -- NOT SOCKS. No provider lets a relay
open raw TCP sockets, only make outbound HTTP(S) requests. Fine for
browsers, Burp, curl, nuclei; not for nmap-style port scans.

CLOUDFLARE REAL-IP LEAK (Cloudflare only): Cloudflare appends your real IP
to X-Forwarded-For / CF-Connecting-IP after worker.js runs, so it can't be
stripped -- any target reading those headers sees you. GCP and Azure are
not affected (verified live); prefer them if that matters. Full detail in
README.md's Limitations.

Setup (once):
    pip install -r requirements.txt
    prism init      # walks you through picking a provider
                               # and its credentials

Switching providers later:
    prism init --switch-provider   # re-show the provider menu
    prism init --provider gcp      # ...or jump straight to one
    (Confirms first, then tears down the old provider's relays.)

Typical engagement:
    prism up            # prompt for a count (1-6), deploy, block
    prism up --count 6  # ...or skip the prompt with a count
    ... point Burp / curl at 127.0.0.1:9292 ...
    <Ctrl+C>                       # stop the rotator, tear down relays

Point a tool at the rotator (127.0.0.1:9292) in one of four ways
(full examples in README.md's "Example usage"):

  1. The tool's own proxy flag, where it has one:
        curl  -x http://127.0.0.1:9292 https://httpbin.org/ip
        o365spray   --proxy http://127.0.0.1:9292
        TREVORspray --proxy http://127.0.0.1:9292      (v2 branch only)

  2. The HTTP_PROXY / HTTPS_PROXY env vars -- nuclei, ffuf, and most
     Go/Python tools honor these with no flag of their own:
        export HTTP_PROXY=http://127.0.0.1:9292        (Linux/macOS)
        $env:HTTP_PROXY = "http://127.0.0.1:9292"      (Windows PowerShell)

  3. proxychains, for tools with neither (e.g. gstrike, MSOLSpray):
        prism up --socks5
        proxychains4 <tool and its args>
        # first add to proxychains.conf's [ProxyList]:  socks5 127.0.0.1 9292

  4. A config-file proxy field, e.g. TeamFiltration (routes its spray/enum/exfil
     traffic through the rotator -- its proxyEndpoint is built for Burp/mitmproxy,
     which is exactly what this rotator is):
        // in its config.json:  { "proxyEndpoint": "http://127.0.0.1:9292", ... }
        TeamFiltration --config config.json --spray ... --debug

Windows notes:
  - Use curl.exe, not plain `curl` (an alias for Invoke-WebRequest that misparses -x).
  - No proxychains -- use WSL, or point MSOLSpray at a system proxy:
        netsh winhttp set proxy 127.0.0.1:9292         (undo: netsh winhttp reset proxy)

Other commands:
    prism status
    prism list
    prism test
    prism config            # view/toggle knobs (impersonate, IP-burning, pacing, ...)
    prism trust             # make client tools trust the rotator's TLS CA (no admin)
    prism down              # delete every relay

Built with Claude Code (https://claude.com/claude-code).
"""

import argparse
import getpass
import json
import re
import os
import secrets
import shutil
import signal
import site
import socket
import subprocess
import sys
import sysconfig
import time
from pathlib import Path

import prism.cloudflare_relay_manager as cfm
import prism.gcp_relay_manager as gcpm
import prism.azure_relay_manager as azm
import prism.relay_common as rc

BACKENDS = {"cloudflare": cfm, "gcp": gcpm, "azure": azm}

CONFIG_PATH = rc.CONFIG_PATH
ENDPOINTS_PATH = rc.ENDPOINTS_PATH
DEFAULT_PORT = 9292
MIN_RELAYS = 1
MAX_RELAYS = 6
DEFAULT_RELAY_COUNT = 6

PROVIDER_REQUIRED_FIELDS = {
    "cloudflare": ("api_token", "account_id", "auth_token"),
    "gcp": ("gcp_project_id", "auth_token"),
    "azure": ("azure_resource_group", "azure_storage_account", "auth_token"),
}
PROVIDER_LABELS = rc.PROVIDER_LABELS

# Values shipped in prism.json.example -- copying that file
# verbatim to prism.json should count as "not configured".
PLACEHOLDER_VALUES = {
    "PASTE_YOUR_CLOUDFLARE_API_TOKEN_HERE",
    "PASTE_YOUR_CLOUDFLARE_ACCOUNT_ID_HERE",
    "GENERATE_A_LONG_RANDOM_SECRET_HERE",
}

# Relay names become a DNS label (<name>.<something>): lowercase
# letters/digits/hyphens, must start and end with an alphanumeric. Capped
# well under the ~63-char DNS label limit to leave room for the random
# suffix each backend appends per relay.
RELAY_PREFIX_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,45}[a-z0-9])?$")

# Azure storage account names are their own, stricter beast: globally
# unique, lowercase letters and digits ONLY (no hyphens), 3-24 chars.
AZURE_STORAGE_NAME_RE = re.compile(r"^[a-z0-9]{3,24}$")

# GCP project ID syntax (this is GCP's own rule, not a choice made here):
# lowercase letters, digits, and hyphens; must start with a letter; must
# NOT end with a hyphen; 6-30 characters total. Notably, underscores are
# NOT allowed -- "relay_test" fails this even though it looks reasonable.
GCP_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def backend_for(cfg):
    return BACKENDS[rc.current_provider(cfg)]


def _port_available(port):
    """True if the port can be bound right now. Binds 0.0.0.0, not
    127.0.0.1 -- that's what mitmdump's regular proxy mode itself binds
    (confirmed against its own bind-failure error message, which names
    ('0.0.0.0', port)), and on Windows specifically a narrower 127.0.0.1-only
    check can pass even while something else holds 0.0.0.0 on the same port,
    letting this check give a false "clear" right before mitmdump's own bind
    fails anyway. Called twice from cmd_up(): once up front (fail fast
    instead of spending several minutes deploying cloud relays only to
    discover this at the very end) and once again right before actually
    launching mitmdump (that multi-minute deploy gap is a real race window
    -- something can grab the port in between the two checks)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _find_port_owner_cmd(port):
    """The copy-pasteable 'what's holding this port' recipe for the current
    OS, with the real port number already substituted. Shared by both of
    cmd_up()'s port checks so the guidance can't drift between them."""
    if sys.platform == "win32":
        return (f"    netstat -ano | findstr :{port}\n"
                "    taskkill /PID <pid> /F")
    return (f"    lsof -i :{port}\n"
            "    kill <pid>")


def find_mitmdump():
    """Locate the mitmdump executable. shutil.which() alone misses it on
    Windows Store/per-user Python installs, where `pip install` drops
    console scripts (mitmdump.exe) into a user Scripts folder that isn't
    automatically added to PATH -- even though the package installed fine
    into the exact interpreter running this script."""
    exe = shutil.which("mitmdump")
    if exe:
        return exe
    exe_name = "mitmdump.exe" if sys.platform == "win32" else "mitmdump"
    candidates = [Path(sysconfig.get_path("scripts")) / exe_name]
    try:
        # site.getuserbase() alone is missing a "PythonXY" version segment
        # some installs (e.g. the Windows Store Python) insert between the
        # user base and Scripts/site-packages -- getusersitepackages()
        # includes it, so derive Scripts as its sibling instead of guessing.
        user_site = Path(site.getusersitepackages())
        candidates.append(user_site.parent / ("Scripts" if sys.platform == "win32" else "bin") / exe_name)
    except Exception:
        pass
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def _mitmdump_health_hint(output):
    """Turn a failed `mitmdump --version` into a concrete fix. The usual cause
    is a half-built/mismatched dependency in the env mitmdump runs from -- the
    classic being zstandard's compiled backend going missing after a system
    Python upgrade strands an older venv. Give the exact repair commands rather
    than letting the raw traceback reach the user."""
    low = (output or "").lower()
    if "zstandard" in low or "backend_c" in low:
        return (
            "mitmproxy's `zstandard` dependency is present but its compiled backend is\n"
            "missing -- almost always a venv built against an older Python after a system\n"
            "Python upgrade. Repair the environment mitmdump runs from (find its venv name\n"
            "with `pipx list`):\n"
            "\n"
            "    pipx runpip <venv> install --force-reinstall --only-binary=:all: 'zstandard>=0.23.0'\n"
            "    # ...or rebuild that venv on your current Python:\n"
            "    pipx reinstall <venv> --python python3\n"
            "\n"
            "Then confirm it's fixed:  mitmdump --version   (must print with no traceback)"
        )
    if "modulenotfounderror" in low or "importerror" in low:
        return (
            "mitmproxy failed to import a dependency -- its environment is incomplete.\n"
            "Reinstall it where mitmdump runs from (`pipx reinstall <venv>`, name from\n"
            "`pipx list`), then confirm `mitmdump --version` runs clean."
        )
    return (
        "mitmdump is installed but won't start -- its Python environment looks broken.\n"
        "Reinstall mitmproxy (e.g. `pipx reinstall <venv>`) and confirm `mitmdump --version`\n"
        "runs with no traceback."
    )


def _verify_mitmdump(mitmdump, env=None):
    """Run `mitmdump --version` exactly as `up` will launch it, so a broken
    install (missing compiled dep, Python-version mismatch) surfaces in ~1s
    BEFORE any relay is deployed -- not as a raw traceback after a multi-minute
    deploy that then tears itself back down. Returns (ok, combined_output)."""
    try:
        r = subprocess.run(
            [mitmdump, "--version"], env=env,
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False, "mitmdump --version timed out after 30s."
    except OSError as e:
        return False, f"could not execute mitmdump: {e}"
    ok = r.returncode == 0 and "Traceback" not in (r.stderr or "")
    return ok, (r.stdout or "") + (r.stderr or "")


def _is_unset(value):
    # not value.isprintable() catches e.g. a single raw control byte from a
    # failed Ctrl+V paste in the legacy Windows console -- input() happily
    # returns it as a "non-empty" one-character string otherwise, and it
    # would silently pass as configured forever.
    return (
        not value
        or not isinstance(value, str)
        or value in PLACEHOLDER_VALUES
        or not value.isprintable()
    )


def _load_raw_config():
    """Best-effort read of prism.json -- {} if missing or unparsable."""
    if not CONFIG_PATH.exists():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _missing_fields(cfg):
    provider = cfg.get("provider")
    if provider not in rc.PROVIDERS:
        return ["provider"]
    missing = [f for f in PROVIDER_REQUIRED_FIELDS[provider] if _is_unset(cfg.get(f))]
    # A present-but-syntactically-invalid gcp_project_id (e.g. saved before
    # this check existed, or hand-edited) would otherwise pass _is_unset and
    # never trigger the wizard -- every `up` would just fail deploy after
    # deploy against gcloud's own confusing "not a valid project ID" error.
    if (
        provider == "gcp"
        and "gcp_project_id" not in missing
        and not GCP_PROJECT_ID_RE.match(cfg.get("gcp_project_id", ""))
    ):
        missing.append("gcp_project_id")
    return missing


def _random_relay_prefix():
    # Generic 'svc-' rather than 'relay-' -- this prefix becomes part of every
    # deployed resource's name (and the relay URL), so a neutral word avoids
    # advertising the proxy's purpose to anyone listing the resource group.
    return "svc-" + secrets.token_hex(3)


def _random_storage_account_name():
    # Generic prefix on purpose -- a storage name like 'relay...' advertises the
    # account's role; 'storage...' blends in. Azure storage names allow only
    # lowercase letters/digits (no hyphens), 3-24 chars: 7 + 16 = 23, valid.
    return "storage" + secrets.token_hex(8)


def _random_gcp_project_id():
    return "svc-" + secrets.token_hex(4)  # 4 + 8 = 12 chars, valid GCP project ID syntax


def _read_required(label, retry_label, flag_hint, secret=False):
    """Prompt until a real (non-empty, printable) value comes back. Rejects
    a lone control byte from a failed Ctrl+V paste (common in the legacy
    Windows console) instead of silently accepting it as valid text."""
    value = _prompt(label, secret=secret)
    while True:
        if value is None:
            sys.exit(f"\nNo input available -- pass {flag_hint} instead of running interactively.")
        if value == "":
            value = _prompt(retry_label, secret=secret)
            continue
        if not value.isprintable():
            print("  That doesn't look like real text -- looks like a failed paste (Ctrl+V didn't")
            print("  register in this console). Try right-click to paste, or pass it directly:")
            print(f'  {flag_hint} "<value>"')
            value = _prompt(retry_label, secret=secret)
            continue
        return value


def _prompt(label, secret=False):
    """Returns the stripped input, or None if stdin hit EOF (as opposed to
    "" for an empty line) -- callers that retry on a blank answer need to
    tell the two apart, or a closed/exhausted stdin retries forever."""
    text = f"{label}: "
    if secret and not sys.stdin.isatty():
        # getpass.getpass() on Windows reads the raw console device directly
        # and ignores redirected/piped stdin entirely -- it would hang here
        # forever instead of raising EOFError like a normal input() does.
        return None
    try:
        raw = getpass.getpass(text) if secret else input(text)
    except EOFError:
        return None
    except KeyboardInterrupt:
        sys.exit("\n[!] Setup cancelled.")
    return raw.strip()


def _prompt_yes_no(question, default=False):
    """Interactive yes/no. Enter keeps `default`; EOF (piped/exhausted stdin)
    also falls back to `default`, so a non-interactive init just takes defaults
    for these rather than hanging."""
    ans = _prompt(f"{question} [{'Y/n' if default else 'y/N'}]")
    if not ans:  # "" (bare Enter) or None (EOF)
        return default
    return ans.lower().startswith("y")


def _prompt_opsec_knobs(provider, existing):
    """Interactively offer the two most useful opsec knobs at the end of setup,
    explaining what each does first. Returns the fields to merge into the config.
    Everything here is optional and changeable any time with `prism config`.
    Only called when there's a real terminal to ask on."""
    out = {}
    print()
    print("-" * 62)
    print(" Optional opsec settings -- Enter to skip; change any later with `prism config`.")
    print("-" * 62)

    print()
    print(" Browser TLS impersonation (JA3/JA4):")
    if provider in ("gcp", "azure"):
        print("   Makes each relay present a REAL browser's TLS fingerprint to the target")
        print("   instead of the cloud runtime's -- so a login/spray request looks like it")
        print("   came from Chrome, not a script. (Needs a redeploy to ship the library.)")
        if _prompt_yes_no("   Enable browser TLS impersonation?", default=bool(existing.get("impersonate"))):
            out["impersonate"] = True
            print("   -> on. After setup, run `prism up --redeploy` so the relays ship it.")
        else:
            out["impersonate"] = False
    else:
        print("   Not available on Cloudflare (Workers can't control fetch()'s TLS).")
        print("   Skipping -- use GCP or Azure if you want this.")

    print()
    print(" IP-burning (retire relays over time):")
    print("   Automatically retires a relay after it has served N requests -- deploys a")
    print("   fresh one (new IP) and deletes the old -- so no single IP builds up target-")
    print("   side reputation on a long run. (Costs a little extra deploy churn.)")
    cur_burn = existing.get("burn_after_requests", 0)
    if _prompt_yes_no("   Enable IP-burning?", default=bool(cur_burn)):
        default_n = cur_burn or 100
        raw = _prompt(f"   Burn each relay after how many requests? (Enter for {default_n})")
        n = default_n
        if raw:
            if raw.isdigit() and int(raw) > 0:
                n = int(raw)
            else:
                print(f"   Not a positive number -- using {default_n}.")
        out["burn_after_requests"] = n
        print(f"   -> on: relays retire after {n} requests.")
    else:
        out["burn_after_requests"] = 0

    return out


def _prompt_provider(existing_provider):
    print(" Which cloud provider do you want to deploy relays to?")
    print("   1. Cloudflare Workers   -- free, simplest, needs an API token")
    print("   2. GCP Cloud Functions  -- needs a GCP project + the gcloud CLI")
    print("   3. Azure Functions      -- needs a resource group + the az CLI")
    print("=" * 62)
    print()
    default_hint = f" (Enter for '{existing_provider}')" if existing_provider else ""
    mapping = {"1": "cloudflare", "2": "gcp", "3": "azure"}
    while True:
        raw = _prompt(f"Choice: 1/2/3 or the name{default_hint}")
        if raw is None:
            sys.exit("\nNo input available -- pass --provider {cloudflare|gcp|azure} instead.")
        if not raw and existing_provider:
            return existing_provider
        choice = mapping.get(raw.strip().lower(), raw.strip().lower())
        if choice in rc.PROVIDERS:
            return choice
        print("  Enter 1, 2, 3, or the provider name (cloudflare/gcp/azure).")


def _confirm_and_cleanup_on_switch(new_provider, existing):
    """If switching to a different provider AND the old one still has
    relays deployed, ask for confirmation -- and if confirmed, automatically
    tear them down first, rather than leaving them orphaned (still running,
    possibly still billing, with nothing left tracking them). Declining
    cancels the switch entirely. If nothing's deployed under the old
    provider there's nothing destructive about switching, so it proceeds
    without asking."""
    old_provider = existing.get("provider")
    if not old_provider or old_provider == new_provider or old_provider not in rc.PROVIDERS:
        return

    have = [e for e in rc.load_endpoints() if e.get("provider", old_provider) == old_provider]
    if not have:
        return

    print()
    print("=" * 62)
    print(f" Switching provider: '{old_provider}' -> '{new_provider}'")
    print(f" {len(have)} relay(s) are still running under '{old_provider}'.")
    print("=" * 62)

    prompt = (
        f"Are you sure you want to switch to '{new_provider}'? This will shut down and "
        f"delete {len(have)} relay(s) still running under '{old_provider}'. [y/N]"
    )

    if not sys.stdin.isatty():
        sys.exit(
            f"Cannot confirm switching providers non-interactively while '{old_provider}' "
            f"still has {len(have)} relay(s) deployed. Run `prism down` "
            f"first (while provider is still '{old_provider}'), or delete endpoints.json."
        )

    answer = _prompt(prompt)
    if answer not in ("y", "yes"):
        sys.exit("\nCancelled -- provider unchanged.")

    print(f"[*] Tearing down {len(have)} relay(s) under '{old_provider}' before switching...")
    BACKENDS[old_provider].cmd_cleanup(existing)


def _init_cloudflare(overrides, existing):
    print(" Cloudflare Workers setup:")
    print("   1. Go to https://dash.cloudflare.com/profile/api-tokens")
    print("   2. Click 'Create Token' -> use the 'Edit Cloudflare Workers' template")
    print("   3. Set Account Resources and Zone Resources to 'All' -> Continue to summary")
    print("   4. Click 'Create Token' and copy it now -- Cloudflare only shows it once")
    print("   5. Copy your Account ID too (right side of any zone/account dashboard page)")
    print("   6. First time on this account? Enable a *.workers.dev subdomain once:")
    print("      Workers & Pages -> Overview, if you haven't already")
    print("=" * 62)
    print()

    api_token = overrides.get("api_token") or existing.get("api_token")
    if _is_unset(api_token):
        api_token = _read_required(
            "Cloudflare API token", "  required -- Cloudflare API token", "--api-token", secret=True
        )
    else:
        print("[*] api_token: already set, keeping it")

    account_id = overrides.get("account_id") or existing.get("account_id")
    if _is_unset(account_id):
        print("  Find this in the right-hand sidebar of any zone or account dashboard")
        print("  page at https://dash.cloudflare.com (also shown under Workers & Pages -> Overview),")
        print("  or in the URL itself once you're in the dashboard:")
        print("  https://dash.cloudflare.com/<account-id>/...")
        account_id = _read_required(
            "Cloudflare account ID", "  required -- Cloudflare account ID", "--account-id"
        )
    else:
        print(f"[*] account_id: already set ({account_id}), keeping it")

    return {"api_token": api_token, "account_id": account_id}


def _init_gcp(overrides, existing):
    print(" GCP Cloud Functions setup:")
    print()
    if sys.platform in ("linux", "darwin"):
        print("   1. Install the gcloud CLI (Google's official installer, Linux/macOS):")
        print("        curl -sSL https://sdk.cloud.google.com | bash")
        print("      (or https://cloud.google.com/sdk/docs/install for package managers)")
    else:
        print("   1. Install the gcloud CLI:  https://cloud.google.com/sdk/docs/install")
    print()
    print("   2. Authenticate:")
    print("        gcloud auth login")
    print()
    print("   3. Link a billing account to your project. Required before any APIs")
    print("      can be enabled -- even for free-tier usage:")
    print("        - List accounts:  gcloud billing accounts list")
    print("        - None yet?       create one at https://console.cloud.google.com/billing")
    print("        - Link it:        gcloud billing projects link <project-id> --billing-account=<ACCOUNT_ID>")
    print()
    print("   4. Pick a project for the prompt below:")
    print("        - Existing one -- use its project ID (not the display name):")
    print("            gcloud config get-value project")
    print("        - New / dedicated one -- leave the prompt blank (or type a name that")
    print("          doesn't exist yet); `up` creates it and enables the APIs on first deploy.")
    print()
    print("   New to Google Cloud? Free-trial notes, so a failed `up` doesn't surprise you:")
    print("        - $300 in credits over 90 days; nothing is charged unless you upgrade.")
    print("        - Some payment methods ask for a small refundable deposit (e.g. $50) first.")
    print("        - The trial can sit 'pending' for up to 24h. If `up` fails right after you")
    print("          link billing, that's this window -- not a config problem. Wait and retry.")
    print("=" * 62)
    print()

    if not gcpm.find_gcloud():
        print("[!] gcloud CLI not found on PATH -- install it (step 1 above) before running `up`.")
        print("    You can still finish this wizard now; `up` re-checks for gcloud when it deploys.")
        print()

    project_id = overrides.get("gcp_project_id") or existing.get("gcp_project_id")
    if not _is_unset(project_id) and not GCP_PROJECT_ID_RE.match(project_id):
        # Catches a config saved before this validation existed (or hand-
        # edited) holding a syntactically invalid ID, e.g. 'relay_test' --
        # gcloud would just fail deploy after deploy with a confusing "not a
        # valid project ID" error rather than this ever getting fixed.
        print(f"[!] gcp_project_id '{project_id}' isn't valid GCP project ID syntax (lowercase")
        print("    letters/digits/hyphens only, no underscores) -- needs to be re-entered.")
        project_id = None
    if _is_unset(project_id):
        prompt_label = "GCP project ID (Enter for a random one)"
        raw = _prompt(prompt_label)
        while raw and not GCP_PROJECT_ID_RE.match(raw):
            print("  GCP project IDs allow lowercase letters, digits, and hyphens only (no")
            print("  underscores), must start with a letter, must not end with a hyphen, and")
            print("  need to be 6-30 characters -- e.g. 'relay-test', not 'relay_test'.")
            raw = _prompt(prompt_label)
        project_id = raw if raw else _random_gcp_project_id()
        print(f"[*] gcp_project_id: using '{project_id}' (created automatically on next `up` if it doesn't already exist)")
    else:
        print(f"[*] gcp_project_id: already set ({project_id}), keeping it")

    region = overrides.get("gcp_region") or existing.get("gcp_region")
    if not region:
        raw = _prompt("GCP region (Enter for us-central1)")
        region = raw or "us-central1"
    print(f"[*] gcp_region: using '{region}'")

    return {"gcp_project_id": project_id, "gcp_region": region}


def _init_azure(overrides, existing):
    print(" Azure Functions setup:")
    if sys.platform == "linux":
        print("   1. Install the az CLI (Debian/Ubuntu):")
        print("      curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
        print("      (other distros -- Fedora/RHEL/etc.: see")
        print("      https://learn.microsoft.com/cli/azure/install-azure-cli-linux)")
        print("      On Kali (or Debian testing/sid): that command may say it can't find a")
        print("      package for your system and offer 'sudo apt install azure-cli' instead --")
        print("      say NO. That's Kali's own outdated/broken azure-cli package, a known")
        print("      source of internal crashes ('NoneType' object is not callable, deep in")
        print("      az's own code, not a real az error). Tell it which Debian release to use")
        print("      instead: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=bookworm bash")
        print("      Then confirm `which az` shows /opt/az/bin/az, not /usr/bin/az, before continuing.")
    elif sys.platform == "darwin":
        print("   1. Install the az CLI: brew update && brew install azure-cli")
        print("      (see https://learn.microsoft.com/cli/azure/install-azure-cli-macos)")
    else:
        print("   1. Install the az CLI: https://learn.microsoft.com/cli/azure/install-azure-cli")
    print()
    print("   2. Run: az login")
    print("      We suggest using your own tenant (a personal test tenant is fine --")
    print("      no need for Global Admin, just Contributor on the subscription/resource")
    print("      group, which you'll typically already have as the tenant's creator).")
    print("      At the sign-in prompt, click 'Work or school account' -- NOT 'Personal")
    print("      account' -- or you'll hit 'Microsoft account does not exist' (AADSTS50020)")
    print("      even with the right credentials. If prompted ambiguously, add --tenant")
    print("      <tenant-id-or-domain> to `az login` to point it at your tenant directly.")
    print()
    print("   3. Make sure a SUBSCRIPTION is attached to that tenant -- these are two")
    print("      different things: the tenant is the directory/identity you just signed")
    print("      into; a subscription is the separate billing container that actually")
    print("      lets you create resources. A fresh tenant has NO subscription by")
    print("      default. Check with: az account list --output table")
    print("      Nothing listed? Sign in to https://portal.azure.com AS that tenant's")
    print("      account, then https://azure.microsoft.com/free to attach a free trial")
    print("      subscription to it ($200/30 days + 12mo of free services; needs a card")
    print("      for identity verification, won't charge unless you upgrade it later).")
    print("      (`up` registers the Microsoft.Web/Microsoft.Storage resource providers")
    print("      on that subscription automatically the first time you deploy, so you")
    print("      don't need to do that step yourself.)")
    print("=" * 62)
    print()

    if not azm.find_az():
        print("[!] az CLI not found on PATH -- install it (step 1 above) before running `up`.")
        print("    You can still finish this wizard now; `up` re-checks for az when it deploys.")
        print()

    resource_group = overrides.get("azure_resource_group") or existing.get("azure_resource_group")
    if _is_unset(resource_group):
        print("  A resource group is just a folder Azure uses to group related resources")
        print("  together (the function apps this tool deploys, plus their storage account)")
        print("  so they can be managed, billed, and deleted as one unit -- it isn't itself")
        print("  billed, and deleting it deletes everything inside it in one shot. Any name")
        print("  works -- it's created automatically on first deploy if it doesn't already")
        print("  exist. List existing ones with: az group list -o table")
        resource_group = _read_required(
            "Azure resource group name", "  required -- resource group name", "--azure-resource-group"
        )
    else:
        print(f"[*] azure_resource_group: already set ({resource_group}), keeping it")

    storage_account = overrides.get("azure_storage_account") or existing.get("azure_storage_account")
    if _is_unset(storage_account):
        print("  Azure Functions require a storage account behind the scenes to keep track of")
        print("  function code, triggers, and internal state -- it's plumbing Azure needs to")
        print("  run your functions, not something you interact with directly here. One is")
        print("  shared across every relay in this config, not created per-relay.")
        print("  Names must be globally unique across ALL of Azure: lowercase letters and")
        print("  digits only, 3-24 characters, no hyphens. Enter for a random one.")
        prompt_label = "Azure storage account name (Enter for a random one)"
        raw = _prompt(prompt_label)
        while raw and not AZURE_STORAGE_NAME_RE.match(raw.lower()):
            print("  Lowercase letters and digits only, 3-24 characters, no hyphens.")
            raw = _prompt(prompt_label)
        storage_account = raw.lower() if raw else _random_storage_account_name()
        print(f"[*] azure_storage_account: using '{storage_account}'")
    else:
        print(f"[*] azure_storage_account: already set ({storage_account}), keeping it")

    region = overrides.get("azure_region") or existing.get("azure_region")
    if not region:
        raw = _prompt("Azure region (Enter for eastus)")
        region = raw or "eastus"
    print(f"[*] azure_region: using '{region}'")

    return {
        "azure_resource_group": resource_group,
        "azure_storage_account": storage_account,
        "azure_region": region,
    }


PROVIDER_INIT_FUNCS = {"cloudflare": _init_cloudflare, "gcp": _init_gcp, "azure": _init_azure}


def interactive_init(overrides=None, existing=None, force_provider_prompt=False):
    """Walk the user through filling in whatever prism.json is
    missing -- values already present and valid are kept as-is. Used both
    by the `init` subcommand and automatically whenever another command
    finds an incomplete/missing config while attached to a real terminal.

    force_provider_prompt=True (via `init --switch-provider`) re-asks which
    provider to use even if one is already configured, so switching is a
    deliberate action rather than something that only happens via --provider.
    """
    overrides = overrides or {}
    existing = existing or {}

    # Discoverability: the interactive wizard is the only place most people
    # ever see, so point them at the flags that skip these prompts -- there's
    # otherwise no hint from a bare `init` that `init --help` has more.
    if sys.stdin.isatty():
        print("(Tip: every prompt below can be preset with a flag -- run "
              "`prism init --help`")
        print(" to see them, e.g. --provider / --api-token / --relay-prefix / "
              "--force / --switch-provider.)")

    provider = None if force_provider_prompt else (overrides.get("provider") or existing.get("provider"))
    if provider not in rc.PROVIDERS:
        print()
        print("=" * 62)
        print(" No provider configured yet -- let's pick one." if not existing.get("provider")
              else " Let's pick a provider to switch to.")
        print("=" * 62)
        current = existing.get("provider") if existing.get("provider") in rc.PROVIDERS else None
        provider = overrides.get("provider") if overrides.get("provider") in rc.PROVIDERS else _prompt_provider(current)
    _confirm_and_cleanup_on_switch(provider, existing)
    print(f"[*] provider: {provider} ({PROVIDER_LABELS[provider]})")

    required = PROVIDER_REQUIRED_FIELDS[provider]
    already_have = {**existing, **{k: v for k, v in overrides.items() if v}}
    missing = [f for f in required if _is_unset(already_have.get(f))]

    print()
    print("=" * 62)
    if missing:
        print(f" {CONFIG_PATH} ({provider}) is missing: {', '.join(missing)} -- let's fill it in.")
    elif existing:
        print(f" {CONFIG_PATH} ({provider}) looks complete -- just confirming a couple of things.")
    else:
        print(f" No {CONFIG_PATH} found -- let's set one up for {PROVIDER_LABELS[provider]}.")
    print("=" * 62)
    print()

    provider_fields = PROVIDER_INIT_FUNCS[provider](overrides, existing)

    auth_token = overrides.get("auth_token") or existing.get("auth_token")
    if _is_unset(auth_token):
        generated = secrets.token_urlsafe(32)
        prompt_label = "Relay auth secret (Enter to auto-generate one, or paste your own)"
        pasted = _prompt(prompt_label)
        while pasted and not pasted.isprintable():
            print("  That doesn't look like real text -- looks like a failed paste (Ctrl+V didn't")
            print("  register in this console). Try right-click to paste, press Enter to auto-generate,")
            print('  or pass it directly: --auth-token "<value>"')
            pasted = _prompt(prompt_label)
        auth_token = pasted or generated
    else:
        print("[*] auth_token: already set, keeping it")

    relay_prefix = overrides.get("relay_prefix") or existing.get("relay_prefix")
    if not relay_prefix:
        prompt_label = "Relay name prefix (Enter for a random one)"
        raw = _prompt(prompt_label)
        while raw and not RELAY_PREFIX_RE.match(raw.lower()):
            print("  Use lowercase letters, digits, and hyphens only, starting and ending")
            print("  with a letter or digit (this becomes part of a relay's URL).")
            raw = _prompt(prompt_label)
        relay_prefix = raw.lower() if raw else _random_relay_prefix()
        print(f"[*] relay_prefix: using '{relay_prefix}'")
    else:
        print(f"[*] relay_prefix: already set ({relay_prefix}), keeping it")

    # Optional opsec knobs, offered only when there's a terminal to ask on --
    # a piped/flag-driven init skips them and leaves them at their defaults.
    # They're also togglable any time with `prism config`, so this is purely a
    # convenience (with an explanation of what each does) at setup time.
    extra_knobs = _prompt_opsec_knobs(provider, existing) if sys.stdin.isatty() else {}

    cfg = {
        **existing,  # keep other providers' leftover fields if switching back later
        **extra_knobs,
        **provider_fields,
        "provider": provider,
        "auth_token": auth_token,
        "relay_prefix": relay_prefix,
    }
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX permissions

    print()
    print(f"[+] Wrote {CONFIG_PATH}")
    print("    Keep this file out of version control -- it holds live credentials.")
    print()
    return cfg


def _looks_complete(cfg):
    # relay_prefix is intentionally not in PROVIDER_REQUIRED_FIELDS (it's
    # optional -- each backend just generates a random one at deploy time
    # if it's missing), but `init` with no args should still offer a
    # one-time prompt for it rather than treating an old config as done.
    return not _missing_fields(cfg) and bool(cfg.get("relay_prefix"))


def cmd_init(args):
    existing = {} if args.force else _load_raw_config()
    override_given = any([
        args.provider, args.switch_provider, args.api_token, args.account_id,
        args.auth_token, args.relay_prefix,
        args.gcp_project_id, args.gcp_region,
        args.azure_resource_group, args.azure_storage_account, args.azure_region,
    ])
    if existing and _looks_complete(existing) and not args.force and not override_given:
        sys.exit(f"{CONFIG_PATH} already exists and looks complete. Pass --force to overwrite it.")
    interactive_init(
        overrides={
            "provider": args.provider,
            "api_token": args.api_token,
            "account_id": args.account_id,
            "auth_token": args.auth_token,
            "relay_prefix": args.relay_prefix,
            "gcp_project_id": args.gcp_project_id,
            "gcp_region": args.gcp_region,
            "azure_resource_group": args.azure_resource_group,
            "azure_storage_account": args.azure_storage_account,
            "azure_region": args.azure_region,
        },
        existing=existing,
        force_provider_prompt=args.switch_provider,
    )


def ensure_config(allow_wizard=True):
    """Load prism.json, or -- if it's missing any required field
    and we're attached to a real terminal -- run the setup wizard on the
    spot to fill in just what's missing. Deliberately does NOT ask about
    relay_prefix here -- that only matters when actually deploying new
    relays, so `down`/`list`/`test`/`status` shouldn't be gated on it (see
    ensure_relay_prefix(), called from cmd_up specifically).

    allow_wizard=False is for commands that act on an ALREADY-deployed session
    (`test`/`list`/`down`): a missing config there almost always means you're in
    the wrong directory, not that you want to set up from scratch, so point that
    out instead of springing the deploy wizard on them."""
    existing = _load_raw_config()
    missing = _missing_fields(existing)
    if not missing:
        return cfm.load_config()
    if not allow_wizard:
        where = os.environ.get("PRISM_HOME") or os.getcwd()
        sys.exit(rc.highlight_commands(
            f"[!] No usable prism.json found (looked in: {where}).\n"
            "\n"
            "    This command works on relays you've already deployed, so it needs the\n"
            "    prism.json + endpoints.json created when you ran `prism up` -- and those\n"
            "    live in the directory you ran it from, not here. Either:\n"
            "\n"
            "      - cd to the folder where you ran `prism up`, or\n"
            "      - point PRISM_HOME at it:  export PRISM_HOME=/path/to/that/folder\n"
            "\n"
            "    (To configure a brand-new provider instead, run `prism init`.)"
        ))
    if not sys.stdin.isatty():
        sys.exit(
            f"{CONFIG_PATH} is missing: {', '.join(missing)}, and there's no terminal to prompt on. Run:\n"
            f"  prism init --provider {{cloudflare|gcp|azure}} ..."
        )
    interactive_init(existing=existing)
    return cfm.load_config()


def ensure_relay_prefix(cfg):
    """Called from cmd_up right before actually deploying new relays. If
    relay_prefix is already set, no-op. Otherwise prompt for one (custom or
    random) when there's a terminal to ask on; non-interactively, just
    leave it unset -- each backend's name_prefix() generates a random one
    at deploy time rather than blocking automation on a prompt."""
    if cfg.get("relay_prefix") or not sys.stdin.isatty():
        return cfg
    interactive_init(existing=_load_raw_config())
    return cfm.load_config()


def will_reuse_endpoints(redeploy):
    """True if `up` will reuse endpoints.json as-is rather than deploying."""
    have = rc.load_endpoints()
    return bool(have) and not redeploy


def _prompt_relay_count():
    while True:
        raw = _prompt(f"How many relays do you want to deploy? ({MIN_RELAYS}-{MAX_RELAYS})")
        if raw is None:
            sys.exit(f"\nNo input available -- pass --count (an integer {MIN_RELAYS}-{MAX_RELAYS}) instead.")
        if not raw:
            print(f"  Enter a whole number from {MIN_RELAYS} to {MAX_RELAYS}.")
            continue
        try:
            n = int(raw)
        except ValueError:
            print(f"  Enter a whole number from {MIN_RELAYS} to {MAX_RELAYS}.")
            continue
        if not (MIN_RELAYS <= n <= MAX_RELAYS):
            print(f"  Enter a whole number from {MIN_RELAYS} to {MAX_RELAYS}.")
            continue
        return n


def ensure_endpoints(cfg, count, redeploy):
    backend = backend_for(cfg)
    have = rc.load_endpoints()
    if have and redeploy:
        print(f"[*] --redeploy given, tearing down {len(have)} existing relay(s) first...")
        backend.cmd_cleanup(cfg)
        have = []
    if have:
        print(f"[*] Reusing {len(have)} existing endpoint(s) from {ENDPOINTS_PATH} (pass --redeploy for a fresh batch)")
        return have
    print(f"[*] Deploying {count} relay(s) via {PROVIDER_LABELS[rc.current_provider(cfg)]}...")
    backend.cmd_create(cfg, count)
    return rc.load_endpoints()


def cmd_up(args):
    # `up` is a long-lived, streaming command that then blocks on the mitmdump
    # child. Make its status lines ("Starting rotator", the Ctrl+C confirm
    # prompt, "Shutting down") line-buffered so they reach the terminal -- or a
    # redirected log/pipe -- the moment they're printed, instead of sitting in a
    # block buffer behind the blocking child until exit. Without this, `up
    # >file` (or any non-TTY stdout) shows nothing while the rotator is running.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    # Force our own SIGINT handling on. A shell that launches `up` in the
    # background (`up &`, or from a non-interactive automation/test script) sets
    # the child's SIGINT disposition to SIG_IGN, and Python inherits and keeps
    # it ignored -- so the Ctrl+C / `kill -INT` confirm-and-teardown flow below
    # would silently never fire. Installing the default handler explicitly
    # restores it regardless of how we were launched (a foreground terminal
    # already gives us SIG_DFL, so this is a no-op there).
    try:
        signal.signal(signal.SIGINT, signal.default_int_handler)
    except (ValueError, OSError):
        pass  # e.g. not on the main thread -- fall back to inherited behavior

    if not _port_available(args.port):
        sys.exit(rc.highlight_commands(
            f"Port {args.port} is already in use -- can't start the rotator there.\n"
            "\n"
            "This is usually a mitmdump left over from a previous `up` whose terminal\n"
            "was force-closed instead of shut down with Ctrl+C.\n"
            "\n"
            "Find and stop it:\n"
            f"{_find_port_owner_cmd(args.port)}\n"
            "\n"
            "Or pick a different port:\n"
            f"    prism up --port {args.port + 1}"
        ))

    cfg = cfm.load_config()
    backend = backend_for(cfg)

    count = args.count
    if not will_reuse_endpoints(args.redeploy):
        # Only bother asking about a relay prefix or validating a count when
        # we're actually about to deploy -- if endpoints.json is being
        # reused as-is, either one here would just be ignored.
        cfg = ensure_relay_prefix(cfg)
        if count is None:
            if sys.stdin.isatty():
                count = _prompt_relay_count()
            else:
                count = DEFAULT_RELAY_COUNT
        elif not (MIN_RELAYS <= count <= MAX_RELAYS):
            sys.exit(f"--count must be between {MIN_RELAYS} and {MAX_RELAYS} (got {count}).")

    # Verify the local rotator engine (mitmdump) is present AND actually runs
    # BEFORE spending minutes deploying relays. A broken mitmdump caught here is
    # a ~1-second, fixable message; caught after deploy it's a raw traceback
    # plus a wasted deploy that then tears itself back down.
    mitmdump = find_mitmdump()
    if not mitmdump:
        if sys.platform == "linux":
            install_hint = (
                "Install it:\n"
                "    sudo apt install mitmproxy\n"
                "\n"
                "Debian-based distros (Kali included) block system-wide pip installs with\n"
                "\"error: externally-managed-environment\" (PEP 668), so to use pip instead:\n"
                "    pipx install mitmproxy\n"
            )
        else:
            install_hint = (
                "Install it:\n"
                "    python3 -m pip install -r requirements.txt\n"
            )
        sys.exit(rc.highlight_commands(
            f"mitmdump not found on PATH, or next to {sys.executable}.\n"
            "\n"
            f"{install_hint}"
            "\n"
            "Then check it's on PATH:\n"
            "    mitmdump --version\n"
            "\n"
            "If that works but `up` still can't find it, mitmproxy may have half-built\n"
            "-- see requirements.txt's note on the zstandard dependency."
        ))

    # Same PYTHONPATH the real launch uses, so the preflight reproduces it faithfully.
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    preflight_env = os.environ.copy()
    _existing_pp = preflight_env.get("PYTHONPATH", "")
    preflight_env["PYTHONPATH"] = pkg_parent + (os.pathsep + _existing_pp if _existing_pp else "")
    ok, out = _verify_mitmdump(mitmdump, preflight_env)
    if not ok:
        sys.exit(rc.highlight_commands(
            f"[!] Found mitmdump at {mitmdump}, but it won't start -- not deploying any relays.\n"
            "\n"
            f"{(out or '').strip()[-800:]}\n"
            "\n"
            + _mitmdump_health_hint(out)
        ))

    endpoints = ensure_endpoints(cfg, count, args.redeploy)
    if not endpoints:
        sys.exit("No endpoints available -- deploy failed, see errors above.")

    addon_path = Path(__file__).resolve().parent / "rotator_addon.py"
    if not addon_path.exists():
        sys.exit(f"Missing {addon_path}")

    # Re-check the port right before actually starting mitmdump, not just
    # once up front. Deploying (especially GCP/Azure, a few minutes for
    # several relays) leaves a real window between the first check above and
    # the actual bind -- something else can grab the port in that gap, and
    # relays are already live by this point, so failing here needs to clean
    # up after itself rather than just exiting and leaving them orphaned.
    if not _port_available(args.port):
        print(rc.highlight_commands(
            f"[!] Port {args.port} was free when `up` started but something took it during\n"
            "    the deploy. Not starting the rotator.\n"
            "\n"
            "Find and stop it:\n"
            f"{_find_port_owner_cmd(args.port)}\n"
            "\n"
            "Or re-run with a different --port."
        ))
        if args.keep:
            print(
                f"[*] --keep given, leaving {len(endpoints)} relay(s) deployed -- re-run `up` "
                "once the port is free and it'll reuse them, or run `down` to tear them down."
            )
        else:
            print("[*] Tearing down the relay(s) just deployed (pass --keep to skip this next time)...")
            backend.cmd_cleanup(cfg)
        sys.exit(1)

    print(f"\n[+] {len(endpoints)} relay(s) ready on {PROVIDER_LABELS[rc.current_provider(cfg)]}.")
    # Nudge, don't auto-enable: browser TLS impersonation works on GCP/Azure but
    # needs curl_cffi shipped in the relay (a redeploy), so it's opt-in. Surface
    # it here rather than turning it on silently (Cloudflare can't do it at all).
    if rc.current_provider(cfg) in ("gcp", "azure") and not cfg.get("impersonate"):
        print('    tip: browser TLS impersonation (JA3/JA4) is available here but off. Enable with')
        print('         `prism config impersonate on`, then `prism up --redeploy`, so the target')
        print('         sees a real-browser fingerprint instead of the runtime default.')
    if args.socks5:
        print(f"[+] Starting rotator on 127.0.0.1:{args.port} (SOCKS5 mode) ...")
        print("    Same relay pool, same rotator_addon.py logic -- just reachable as a SOCKS5")
        print("    proxy instead of HTTP(S), for tools that speak SOCKS but not a plain --proxy")
        print("    flag (e.g. wrapping a proxy-unaware tool with `proxychains`).")
        print("    Point clients at it, e.g.:")
        print(rc.highlight_commands(f"      curl --socks5 127.0.0.1:{args.port} https://httpbin.org/ip"))
        print(f"      # or add to proxychains.conf's [ProxyList]: socks5 127.0.0.1 {args.port}")
        print("      # then:  proxychains4 <command that has no proxy support of its own>")
    else:
        print(f"[+] Starting rotator on 127.0.0.1:{args.port} ...")
        print("    HTTP(S) only -- not SOCKS. Fine for browsers/Burp/curl; not for nmap-style scans.")
        print("    (pass --socks5 next time for a SOCKS5 listener instead -- useful for tools")
        print("    with no native proxy support at all, via `proxychains`)")
        print("    Point clients at it, e.g.:")
        if sys.platform == "win32":
            # PowerShell has no `export` -- and its `curl` is aliased to
            # Invoke-WebRequest, which silently misparses curl-only flags like
            # -x/--proxy, so curl.exe (the real binary) is called explicitly.
            print(rc.highlight_commands(f'      $env:HTTPS_PROXY = "http://127.0.0.1:{args.port}"'))
            print(rc.highlight_commands(f'      $env:HTTP_PROXY = "http://127.0.0.1:{args.port}"'))
            print(rc.highlight_commands(f"      curl.exe --proxy http://127.0.0.1:{args.port} https://httpbin.org/ip"))
        else:
            print(rc.highlight_commands(f"      export HTTPS_PROXY=http://127.0.0.1:{args.port}"))
            print(rc.highlight_commands(f"      export HTTP_PROXY=http://127.0.0.1:{args.port}"))
            print(rc.highlight_commands(f"      curl -x http://127.0.0.1:{args.port} https://httpbin.org/ip"))
    print(rc.highlight_commands(
        "    First HTTPS client needs to trust mitmproxy's CA -- run `prism trust` in another"))
    print("    terminal for copy-paste env exports (no admin), or visit http://mitm.it while proxied.")
    print("    Ctrl+C to stop (you'll be asked to confirm).\n")

    # Put the child in its own process group/session so a raw Ctrl+C from the
    # console doesn't kill it outright -- only this parent process catches the
    # interrupt, so it can prompt for confirmation before touching anything.
    child_kwargs = {}
    if sys.platform == "win32":
        child_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        child_kwargs["start_new_session"] = True

    # mitmdump loads rotator_addon.py in a separate process and only puts the
    # addon's OWN directory (the package dir) on sys.path -- not the directory
    # above it, which is what makes `prism` importable as a package. Without
    # that, the addon's `import prism.*` (and the managers' `from prism...`)
    # fail on load, mitmdump exits, and every proxied request gets nothing.
    # Propagate the package's parent -- the repo root when running from source,
    # site-packages when installed (harmless there, already on the path) -- via
    # PYTHONPATH so the child can import the package either way.
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    child_env = os.environ.copy()
    existing_pp = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = pkg_parent + (os.pathsep + existing_pp if existing_pp else "")
    child_kwargs["env"] = child_env

    mitmdump_args = [mitmdump, "-s", str(addon_path), "-p", str(args.port)]
    if args.socks5:
        # Verified directly (not assumed): mitmdump's own --mode socks5 spawns
        # a real SOCKS5 listener, and rotator_addon.py's request()/response()
        # hooks fire identically through it -- mode only changes how a client
        # tells mitmproxy what to connect to, not how the addon pipeline
        # processes HTTP(S) traffic once a connection is established. Tested
        # end-to-end against a local stand-in relay before shipping this.
        mitmdump_args += ["--mode", "socks5"]
    proc = subprocess.Popen(mitmdump_args, **child_kwargs)
    start_time = time.monotonic()
    rotator_crashed = False

    while True:
        try:
            # Poll-with-sleep instead of a blocking proc.wait(): on Windows,
            # Ctrl+C is delivered to a separate console-control-handler
            # thread, and the pending KeyboardInterrupt is only actually
            # raised in the main thread the next time the interpreter checks
            # for it between bytecode instructions -- a single long blocking
            # OS-level wait (what proc.wait() does under the hood) can give
            # it no such opportunity, so Ctrl+C is silently swallowed or
            # badly delayed. time.sleep() in a loop checks far more often
            # and is the standard, reliable fix for this well-known
            # Windows/Python limitation.
            while proc.poll() is None:
                time.sleep(0.25)
            # Rotator exited on its own rather than on a user Ctrl+C. If it
            # died within a few seconds of starting it never really ran -- a
            # startup crash, not a finished session -- so flag it and skip the
            # "also delete your cloud infra?" offer below (that prompt is for a
            # deliberate shutdown, not a crash the user is about to go fix).
            if time.monotonic() - start_time < 5:
                rotator_crashed = True
            break
        except KeyboardInterrupt:
            # mitmdump keeps streaming log lines to this same terminal while
            # we prompt -- in tmux especially, that interleaves with the
            # echoed keystroke and can garble it (e.g. Enter showing as ^J).
            # Briefly SIGSTOP it so the prompt has the terminal to itself.
            paused = False
            if sys.platform != "win32":
                try:
                    proc.send_signal(signal.SIGSTOP)
                    paused = True
                except (ProcessLookupError, OSError):
                    pass

            sys.stdout.flush()
            # Print the prompt explicitly (flushed, no trailing newline) rather
            # than relying on input()'s prompt argument: when stdout is a
            # redirected log/pipe, input() may not flush its prompt, leaving the
            # confirm invisible. This way it always appears -- terminal or log.
            print("\nAre you sure you want to shut down this tool? [y/N] ", end="", flush=True)
            try:
                answer = input().strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Shutting down.")
                break

            if answer in ("y", "yes"):
                print("[*] Shutting down...")
                break

            print("[*] Staying up -- rotator keeps running. Ctrl+C again to stop.\n")
            if paused:
                try:
                    proc.send_signal(signal.SIGCONT)
                except (ProcessLookupError, OSError):
                    pass

    if proc.poll() is None:
        # A stopped process ignores SIGTERM until continued -- make sure
        # it's running before we ask it to exit.
        if sys.platform != "win32":
            try:
                proc.send_signal(signal.SIGCONT)
            except (ProcessLookupError, OSError):
                pass
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    if rotator_crashed:
        print(rc.highlight_commands(
            "\n[!] The rotator exited right after starting -- it didn't stay up. This is a\n"
            "    local mitmdump problem, not your relays. Check it directly:\n"
            "        mitmdump --version\n"
            "    If that shows a traceback, fix that install and run `up` again."
        ))

    if args.keep:
        print(f"[*] --keep given, leaving {len(endpoints)} relay(s) deployed. Run `down` when the engagement ends.")
    else:
        print("[*] Tearing down relays (pass --keep to skip this next time)...")
        backend.cmd_cleanup(cfg)
        # Only offer the destructive infra-purge after a deliberate shutdown --
        # never after a crash, when the user is mid-debugging and a stray "y"
        # would delete their resource group out from under the next attempt.
        if not rotator_crashed:
            _maybe_offer_azure_purge(cfg)


def _maybe_offer_azure_purge(cfg):
    """After relays are torn down, Azure users get one extra offer to also
    clean up the resource group and storage account -- shared
    infrastructure cmd_cleanup() deliberately leaves in place otherwise.
    Only ever asked, never automatic, and reuses the exact same interactive
    picker `down --purge-infra` exposes explicitly (list what exists, pick
    by number or name, type the name back to confirm each deletion). Asked
    right here rather than only via that flag because a spontaneous
    Ctrl+C-triggered teardown mid-`up` is exactly the moment someone
    decides they're actually done -- not something to expect them to have
    remembered a flag for back when they first ran `up`, possibly hours
    earlier."""
    if rc.current_provider(cfg) != "azure" or not sys.stdin.isatty():
        return
    answer = _prompt(
        "Also delete the Azure resource group and storage account? This lists what "
        "exists on the subscription and asks before deleting anything. [y/N]"
    )
    if answer in ("y", "yes"):
        azm.cmd_purge_infra(cfg)


def cmd_down(args):
    cfg = cfm.load_config()
    backend_for(cfg).cmd_cleanup(cfg)
    if getattr(args, "purge_infra", False):
        provider = rc.current_provider(cfg)
        if provider != "azure":
            print(
                f"\n[*] --purge-infra is currently only implemented for Azure; nothing "
                f"further to do for {PROVIDER_LABELS[provider]}."
            )
        else:
            azm.cmd_purge_infra(cfg)
    else:
        _maybe_offer_azure_purge(cfg)


def cmd_list(args):
    cfg = cfm.load_config()
    backend_for(cfg).cmd_list(cfg)


def cmd_test(args):
    cfg = cfm.load_config()
    backend_for(cfg).cmd_test(cfg, fingerprint=getattr(args, "fingerprint", False))


# Tunable rotator knobs -- kept out of the wizard (they default to off/tested
# baseline), but togglable here so nobody has to hand-edit prism.json.
CONFIG_SETTINGS = ("impersonate", "burn", "burn-time", "pacing", "sticky", "upstream-proxy")
_ONOFF = {"on": True, "true": True, "1": True, "yes": True,
          "off": False, "false": False, "0": False, "no": False, "none": False}


def _save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        CONFIG_PATH.chmod(0o600)  # holds credentials; best-effort on non-POSIX
    except OSError:
        pass


def _onoff(v):
    return "on" if v else "off"


def _int_or_off(label, v):
    if v.lower() in ("off", "none"):
        return 0
    if not v.isdigit():
        sys.exit(f"[!] `config {label}` wants a number or 'off', got {v!r}")
    return int(v)


def _show_config(cfg):
    br, bs = cfg.get("burn_after_requests", 0), cfg.get("burn_after_seconds", 0)
    pmin, pmax = cfg.get("pacing_min_seconds", 0), cfg.get("pacing_max_seconds", 0)
    # (knob, current value, what it's for) -- the third column tells the user
    # what changing it actually does, so they're not editing values blind.
    rows = [
        ("impersonate", _onoff(cfg.get("impersonate")),
         "relay presents a real browser TLS/JA3/JA4 fingerprint (GCP/Azure only)"),
        ("burn", (f"after {br} requests" if br else "off"),
         "retire a relay after N requests (fresh IP) so no IP builds reputation"),
        ("burn-time", (f"after {bs}s" if bs else "off"),
         "same, but retire by how long a relay has been in the pool"),
        ("pacing", (f"{pmin}-{pmax}s" if pmax else "off"),
         "random delay before each request, to dodge velocity/rate detection"),
        ("sticky", f"{cfg.get('sticky_seconds', 300)}s",
         "keep one relay+identity per (client,target) this long (0 = fresh each time)"),
        ("upstream-proxy", (cfg.get("upstream_proxy") or "off"),
         "send the rotator->relay leg via a burner (hides you from Cloudflare's XFF leak)"),
    ]
    print("Rotator knobs -- change with `prism config <knob> <value>`:\n")
    for knob, val, purpose in rows:
        print(f"  {knob:<15}{val:<19}{purpose}")


def cmd_config(args):
    if not CONFIG_PATH.exists():
        sys.exit(f"[!] No {CONFIG_PATH} yet -- run `prism init` first.")
    cfg = json.loads(CONFIG_PATH.read_text())

    if not args.setting:
        _show_config(cfg)
        return

    key, vals = args.setting, args.value

    def need(n):
        if len(vals) < n:
            sys.exit(f"[!] `config {key}` needs {n} value(s). See `prism config --help`.")

    if key == "impersonate":
        need(1)
        v = vals[0].lower()
        if v not in _ONOFF:
            sys.exit(f"[!] `config impersonate` wants on/off, got {vals[0]!r}")
        cfg["impersonate"] = _ONOFF[v]
    elif key == "burn":
        need(1)
        cfg["burn_after_requests"] = _int_or_off("burn", vals[0])
    elif key == "burn-time":
        need(1)
        cfg["burn_after_seconds"] = _int_or_off("burn-time", vals[0])
    elif key == "pacing":
        need(1)
        if vals[0].lower() in ("off", "none", "0"):
            cfg["pacing_min_seconds"] = cfg["pacing_max_seconds"] = 0
        else:
            need(2)
            try:
                mn, mx = float(vals[0]), float(vals[1])
            except ValueError:
                sys.exit(f"[!] `config pacing` wants two numbers (min max) or 'off', got {vals!r}")
            if mn < 0 or mx < mn:
                sys.exit("[!] pacing needs 0 <= min <= max")
            cfg["pacing_min_seconds"], cfg["pacing_max_seconds"] = mn, mx
    elif key == "sticky":
        need(1)
        cfg["sticky_seconds"] = _int_or_off("sticky", vals[0])
    elif key == "upstream-proxy":
        need(1)
        cfg["upstream_proxy"] = None if vals[0].lower() in ("off", "none") else vals[0]

    _save_config(cfg)
    print(f"[+] Updated {CONFIG_PATH}.\n")
    _show_config(cfg)
    # How the change takes effect: the rotator reads prism.json at startup, so a
    # running session needs a restart; impersonation additionally needs the relay
    # redeployed with curl_cffi.
    print()
    if key == "impersonate" and cfg.get("impersonate"):
        print("    Note: run `prism up --redeploy` so the relays ship curl_cffi, then")
        print("          `prism test --fingerprint` to confirm the browser fingerprint.")
    else:
        print("    Note: restart the rotator (Ctrl+C, then `prism up`) to apply.")


def _mitm_confdir():
    return Path.home() / ".mitmproxy"


def _mitm_ca_cert():
    # mitmproxy generates this on the rotator's first start; it's per-machine.
    return _mitm_confdir() / "mitmproxy-ca-cert.pem"


def cmd_trust(args):
    """Make client tools trust the rotator's TLS without hand-exporting certs.

    The rotator is mitmproxy: it must terminate TLS locally to read a request
    and rewrite it into the relay protocol, so clients have to trust its CA or
    they get cert errors. Rather than make people wrangle that, we build one
    combined bundle (the standard CA set + mitmproxy's CA, so normal HTTPS still
    validates) and print the env exports that point tools at it -- no admin, no
    system-store changes, scoped to the shell."""
    ca = _mitm_ca_cert()
    if not ca.exists():
        print(rc.highlight_commands(
            "[!] mitmproxy's CA doesn't exist yet -- it's generated the first time the rotator\n"
            "    starts. Run `prism up` once (Ctrl+C to stop it), then re-run `prism trust`."
        ))
        return

    import certifi
    bundle = _mitm_confdir() / "prism-ca-bundle.pem"
    try:
        bundle.write_bytes(Path(certifi.where()).read_bytes() + b"\n" + ca.read_bytes())
    except OSError as e:
        sys.exit(f"[!] Couldn't write the combined bundle: {e}")

    print("Trust the rotator's TLS -- point your tools at this bundle (no admin needed):")
    print(f"  mitmproxy CA:    {ca}")
    print(f"  combined bundle: {bundle}  (standard CAs + mitmproxy's, so normal HTTPS still works)")
    print()
    print("Paste these in the shell you run your tools from:")
    if sys.platform == "win32":
        print(rc.highlight_commands(f'  $env:REQUESTS_CA_BUNDLE = "{bundle}"   # Python requests: o365spray, TREVORspray, MSOLSpray'))
        print(rc.highlight_commands(f'  $env:CURL_CA_BUNDLE = "{bundle}"       # curl.exe'))
        print(rc.highlight_commands(f'  $env:SSL_CERT_FILE = "{bundle}"        # other Python/OpenSSL tools'))
        print(rc.highlight_commands(f'  $env:NODE_EXTRA_CA_CERTS = "{ca}"      # Node tools (gstrike)'))
    else:
        print(rc.highlight_commands(f'  export REQUESTS_CA_BUNDLE="{bundle}"   # Python requests: o365spray, TREVORspray, MSOLSpray'))
        print(rc.highlight_commands(f'  export CURL_CA_BUNDLE="{bundle}"       # curl'))
        print(rc.highlight_commands(f'  export SSL_CERT_FILE="{bundle}"        # other Python/OpenSSL tools'))
        print(rc.highlight_commands(f'  export NODE_EXTRA_CA_CERTS="{ca}"      # Node tools (gstrike)'))
    print()
    print("Browsers and .NET tools (e.g. TeamFiltration) use the OS trust store instead --")
    print("for those, install the CA system-wide (needs admin):")
    if sys.platform.startswith("linux"):
        print(rc.highlight_commands(f"  sudo cp {ca} /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates"))
    elif sys.platform == "darwin":
        print(rc.highlight_commands(f"  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {ca}"))
    elif sys.platform == "win32":
        print(rc.highlight_commands(f'  certutil -addstore -user Root "{ca}"'))


def cmd_status(args):
    raw = _load_raw_config()
    provider = raw.get("provider") if raw.get("provider") in rc.PROVIDERS else None
    missing = _missing_fields(raw)
    if not missing:
        config_state = "present"
    elif CONFIG_PATH.exists():
        config_state = f"INCOMPLETE, missing {', '.join(missing)} (will prompt on next `up`/`init`)"
    else:
        config_state = "MISSING (will prompt on next `up`/`init`)"
    provider_line = f"provider:  {provider or 'not yet chosen'}" + (f"  ({PROVIDER_LABELS[provider]})" if provider else "")
    print(_colorize(provider_line, provider) if provider else provider_line)
    if provider:
        _set_terminal_title(f"{PROVIDER_LABELS[provider]} -- prism")
    print(f"config:    {config_state}  ({CONFIG_PATH})")
    prefix = raw.get("relay_prefix")
    if prefix:
        print(f"prefix:    {prefix} (each relay is deployed as '{prefix}-<random>')")
    else:
        print("prefix:    not yet set (will prompt for one -- custom or random -- on next run)")
    if ENDPOINTS_PATH.exists():
        n = len(json.loads(ENDPOINTS_PATH.read_text()))
        print(f"endpoints: {n} deployed  ({ENDPOINTS_PATH})")
    else:
        print("endpoints: none deployed")
    mitmdump_path = find_mitmdump()
    if mitmdump_path:
        print(f"mitmdump:  {mitmdump_path}")
    elif sys.platform == "linux":
        print("mitmdump:  NOT found  --  sudo apt install mitmproxy")
    else:
        print("mitmdump:  NOT found  --  python3 -m pip install -r requirements.txt")
    if provider == "gcp":
        gcloud_path = gcpm.find_gcloud()
        if gcloud_path:
            print(f"gcloud:    {gcloud_path}")
        elif sys.platform in ("linux", "darwin"):
            print("gcloud:    NOT found on PATH  --  curl -sSL https://sdk.cloud.google.com | bash")
        else:
            print("gcloud:    NOT found on PATH  --  https://cloud.google.com/sdk/docs/install")
    elif provider == "azure":
        az_path = azm.find_az()
        if az_path:
            print(f"az:        {az_path}")
        elif sys.platform == "linux":
            print("az:        NOT found on PATH  --  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
            print("           (Kali/Debian sid: add DIST_CODE=bookworm -- `up` explains why)")
        elif sys.platform == "darwin":
            print("az:        NOT found on PATH  --  brew update && brew install azure-cli")
        else:
            print("az:        NOT found on PATH  --  https://learn.microsoft.com/cli/azure/install-azure-cli")


class _SubHelpFormatter(argparse.HelpFormatter):
    """Subcommand help formatter: pushes the help text into an aligned second
    column (instead of wrapping under each flag) so grouped option lists read
    as a clean table."""

    def __init__(self, prog):
        super().__init__(prog, max_help_position=28)


def build_parser():
    # Shared as `parents=[debug_parent]` on the main parser AND every
    # subparser, so `--debug` works whether it's typed before or after the
    # subcommand (e.g. both `prism --debug list` and `prism
    # list --debug`). argparse gives each subparser its own namespace and
    # merges it back over the top-level one, so a plain store_true default
    # of False on the subparser copy would silently clobber a True set
    # before the subcommand -- default=SUPPRESS stops that merge from
    # touching `debug` at all unless the flag is actually given there.
    debug_parent = argparse.ArgumentParser(add_help=False)
    debug_parent.add_argument(
        "--debug", action="store_true", default=argparse.SUPPRESS,
        help="Show full tracebacks instead of a one-line error",
    )
    # Same SUPPRESS trick as --debug so it works before or after the subcommand
    # without a subparser's default clobbering a value set at the top level.
    debug_parent.add_argument(
        "--no-banner", action="store_true", default=argparse.SUPPRESS,
        help="Skip the startup animation (also: NO_COLOR / PRISM_NO_BANNER env)",
    )

    parser = argparse.ArgumentParser(
        prog="prism",  # so `python -m prism` also reads "prism", not "__main__.py"
        description=_help_banner() + __doc__, formatter_class=argparse.RawDescriptionHelpFormatter, parents=[debug_parent]
    )
    # NB: deliberately not parser.set_defaults(debug=...) here -- that would
    # mutate the shared --debug Action's .default in place (it's the same
    # object on every subparser via `parents`), undoing the SUPPRESS trick
    # above and reintroducing the clobbering bug. Read it with getattr()
    # instead wherever it's needed.
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init", help="Create prism.json", parents=[debug_parent],
        formatter_class=_SubHelpFormatter,
        description="Create or update prism.json. With no flags it runs an interactive "
                    "wizard; pass the flags below to fill any of it non-interactively. "
                    "Only the flags for your chosen provider are needed.",
        usage="prism init [--provider {cloudflare,gcp,azure}] [provider flags]\n"
              "                 [--auth-token TOKEN] [--relay-prefix PREFIX] [--force]",
    )

    g_sel = p_init.add_argument_group("provider selection")
    g_sel.add_argument("--provider", choices=list(rc.PROVIDERS), help="Which cloud backend to use")
    g_sel.add_argument(
        "--switch-provider", action="store_true",
        help=(
            "Switch to a different provider. Asks which one (add --provider to skip the "
            "menu), confirms, then tears down any relays still running under the old one."
        ),
    )

    g_cf = p_init.add_argument_group("Cloudflare")
    g_cf.add_argument("--api-token", metavar="TOKEN", help="Cloudflare API token")
    g_cf.add_argument("--account-id", metavar="ID", help="Cloudflare account ID")

    g_gcp = p_init.add_argument_group("GCP")
    g_gcp.add_argument("--gcp-project-id", metavar="ID", help="GCP project ID")
    g_gcp.add_argument("--gcp-region", metavar="REGION", help="GCP region, e.g. us-central1")

    g_az = p_init.add_argument_group("Azure")
    g_az.add_argument("--azure-resource-group", metavar="NAME", help="Azure resource group name")
    g_az.add_argument("--azure-storage-account", metavar="NAME", help="Storage account name (lowercase alnum, 3-24 chars)")
    g_az.add_argument("--azure-region", metavar="REGION", help="Azure region, e.g. eastus")

    g_gen = p_init.add_argument_group("general")
    g_gen.add_argument("--auth-token", metavar="TOKEN", help="Use this instead of generating a random one")
    g_gen.add_argument(
        "--relay-prefix", metavar="PREFIX",
        help=(
            "Prefix for every relay name, e.g. 'myproxy' (lowercase letters, digits, "
            "hyphens). Omit to be prompted; blank at the prompt gives a random one. "
            "Settable on its own, without --force."
        ),
    )
    g_gen.add_argument("--force", action="store_true", help="Overwrite an existing config file")
    p_init.set_defaults(func=cmd_init)

    p_up = sub.add_parser(
        "up", help="Deploy relays (if needed) and start the local rotator; blocks until Ctrl+C", parents=[debug_parent]
    )
    p_up.add_argument(
        "--count", type=int, default=None,
        help=f"Number of relays to deploy ({MIN_RELAYS}-{MAX_RELAYS}); omit to be prompted",
    )
    p_up.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Local port for the rotator to listen on (default {DEFAULT_PORT})",
    )
    p_up.add_argument("--redeploy", action="store_true", help="Tear down and redeploy even if endpoints.json already has entries")
    p_up.add_argument("--keep", action="store_true", help="Don't delete relays when the rotator stops")
    p_up.add_argument(
        "--socks5", action="store_true",
        help=(
            "Listen as SOCKS5 instead of HTTP(S) -- for tools with no proxy flag of their "
            "own, wrapped in `proxychains`. Same relays either way."
        ),
    )
    p_up.set_defaults(func=cmd_up)

    p_down = sub.add_parser("down", help="Delete every relay and remove endpoints.json", parents=[debug_parent])
    p_down.add_argument(
        "--purge-infra", action="store_true",
        help=(
            "Azure only. After deleting relays, list every resource group and storage "
            "account on the subscription -- not just the configured ones -- and pick which "
            "to delete, confirming each by typing its name. Deleting a group takes "
            "everything inside it; deleting a storage account alone leaves its group. Off "
            "by default: infra is left in place for reuse."
        ),
    )
    p_down.set_defaults(func=cmd_down)

    p_list = sub.add_parser("list", help="List relays under the active provider", parents=[debug_parent])
    p_list.set_defaults(func=cmd_list)

    p_test = sub.add_parser("test", help="Send a canary request through every endpoint", parents=[debug_parent])
    p_test.add_argument(
        "--fingerprint", action="store_true",
        help="Report the JA3/JA4 TLS fingerprint each relay presents (via an external echo "
             "service) instead of a plain reachability check -- the live check for `impersonate`.",
    )
    p_test.set_defaults(func=cmd_test)

    p_status = sub.add_parser("status", help="Show provider/config/endpoint/mitmdump status", parents=[debug_parent])
    p_status.set_defaults(func=cmd_status)

    p_config = sub.add_parser(
        "config", help="Toggle rotator knobs (impersonate, IP-burning, ...) without editing prism.json",
        parents=[debug_parent], formatter_class=_SubHelpFormatter,
        description="View or change the advanced rotator knobs. Run with no arguments to see "
                    "current values.",
        usage="prism config [<knob> <value>]",
    )
    p_config.add_argument("setting", nargs="?", choices=CONFIG_SETTINGS, metavar="knob",
                          help="one of: " + ", ".join(CONFIG_SETTINGS))
    p_config.add_argument("value", nargs="*", metavar="value",
                          help="impersonate on|off ; burn <N>|off ; burn-time <secs>|off ; "
                               "pacing <min> <max>|off ; sticky <secs> ; upstream-proxy <url>|off")
    p_config.set_defaults(func=cmd_config)

    p_trust = sub.add_parser(
        "trust", help="Print how to make client tools trust the rotator's TLS CA (no hand-editing certs)",
        parents=[debug_parent],
    )
    p_trust.set_defaults(func=cmd_trust)

    return parser


# ANSI SGR color codes per provider. Orange isn't one of the 8 standard
# ANSI colors, so Cloudflare uses a 256-color code instead (widely
# supported by modern terminals, including Windows Terminal/conhost with
# VT processing, which is on by default on Windows 10+).
_ANSI_RESET = "\033[0m"
PROVIDER_COLORS = {
    "cloudflare": "\033[38;5;208m",  # orange
    "gcp": "\033[31m",               # red
    "azure": "\033[34m",             # blue
}


def _color_supported():
    # Only emit escape codes to a real terminal -- redirected/piped output
    # would just get literal garbage characters instead of color.
    return sys.stdout.isatty()


def _colorize(text, provider):
    color = PROVIDER_COLORS.get(provider)
    if not color or not _color_supported():
        return text
    return f"{color}{text}{_ANSI_RESET}"


def _help_banner():
    """Colored ASCII prism shown atop `--help` on a real terminal. The three
    edges map to the three providers -- blue = Azure, orange = Cloudflare,
    red = GCP (the same colors the ACTIVE PROVIDER banner uses). Returns ""
    when stdout isn't a TTY, so no escape codes leak into piped/redirected
    help output (e.g. `prism --help | less`, or `> help.txt`)."""
    if not _color_supported():
        return ""
    return "\n" + "\n".join(_prism_rows("color", -1, _PRISM_N)) + "\n"


# ---- launch splash -------------------------------------------------------
# The startup animation and the static --help banner draw the same prism, so
# they share one geometry + row builder. The three edges map to the three
# providers: blue = Azure (left), orange = Cloudflare (right), red = GCP
# (base) -- the same colors the ACTIVE PROVIDER banner uses.
#
# A shallow N-row triangle (sides step 1-2 cols/row so it reads wide, not
# steep). Everything is centered on one axis -- the tagline is the widest
# element, so it sets the center, and the triangle + wordmark are indented
# onto it -- so the whole logo reads as a centered lockup.
_SPLASH_WORD = "P R I S M"
_SPLASH_TAG = "rotating-source-IP relay mesh"
_PRISM_N = 10                             # triangle rows (taller -> wider base)
_PRISM_AXIS = len(_SPLASH_TAG) // 2       # shared center column (widest line)
_WORD_INDENT = _PRISM_AXIS - len(_SPLASH_WORD) // 2
_TAG_INDENT = max(0, _PRISM_AXIS - len(_SPLASH_TAG) // 2)
_SPLASH_H = _PRISM_N + 3  # triangle + blank + wordmark + tagline (stable height)


def _prism_row_geom(i):
    """(indent, inner) for triangle row i. Strict 45 degrees -- each row moves
    the edges out by exactly one column -- so the sides render as solid,
    connected diagonals (a shallower slope leaves gaps between the marks). The
    horizontal center stays on _PRISM_AXIS every row."""
    inner = 2 * i
    indent = _PRISM_AXIS - 1 - i
    return indent, inner


def _prism_rows(mode, hot, n_rows):
    """Build the prism's edge rows.

    mode  -- "white" (all edges lit white, mid-refraction) or "color" (settled
             into the per-provider edge colors).
    hot   -- a single row index to force bright-white (the beam sweeping an
             edge), or -1 for none.
    n_rows -- how many rows (top-down) are revealed yet; the rest come back
             blank so the block keeps a constant height while it draws in.
    """
    b = PROVIDER_COLORS["azure"]       # left edge  -> blue
    o = PROVIDER_COLORS["cloudflare"]  # right edge -> orange
    r = PROVIDER_COLORS["gcp"]         # base       -> red
    w = "\033[97m"                     # bright white
    x = _ANSI_RESET
    rows = []
    for i in range(_PRISM_N):
        if i >= n_rows:
            rows.append("")
            continue
        indent, inner = _prism_row_geom(i)
        lc = w if (mode == "white" or i == hot) else b
        rc = w if (mode == "white" or i == hot) else o
        if i < _PRISM_N - 1:
            rows.append(f"{' ' * indent}{lc}/{x}{' ' * inner}{rc}\\{x}")
        else:
            bc = w if mode == "white" else r
            rows.append(f"{' ' * indent}{lc}/{x}{bc}{'_' * inner}{x}{rc}\\{x}")
    return rows


def _launch_splash():
    """A brief 'white light through a prism' animation: the prism draws in, a
    white beam runs down its edge, then the light disperses into the three
    provider colors as the wordmark types in. Purely decorative and best-effort
    -- it never blocks or breaks a launch. Silent unless stdout is a real
    terminal, and honors NO_COLOR / PRISM_NO_BANNER / --no-banner."""
    if not _color_supported() or os.environ.get("NO_COLOR") or os.environ.get("PRISM_NO_BANNER"):
        return

    w = "\033[97m"
    dim = "\033[90m"
    x = _ANSI_RESET

    def block(mode, hot, n_rows, word_n):
        lines = _prism_rows(mode, hot, n_rows)
        lines.append("")
        lines.append(f"{' ' * _WORD_INDENT}{w}{_SPLASH_WORD[:word_n]}{x}")
        lines.append(f"{' ' * _TAG_INDENT}{dim}{_SPLASH_TAG}{x}" if mode == "color" else "")
        while len(lines) < _SPLASH_H:
            lines.append("")
        return lines[:_SPLASH_H]

    def draw(lines, first):
        buf = [] if first else [f"\033[{_SPLASH_H}A"]
        for ln in lines:
            buf.append(f"\r\033[K{ln}\n")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()

    first = True
    try:
        sys.stdout.write("\033[?25l")  # hide cursor for the duration
        # One blank line above the prism so its apex doesn't butt right up
        # against the shell prompt / command line. Printed once, before the
        # animation's first frame -- the per-frame redraw only moves the cursor
        # up _SPLASH_H lines (to the apex), so this spacer is never overwritten.
        sys.stdout.write("\n")
        for n in range(1, _PRISM_N + 1):   # phase 1: prism draws in, top-down
            draw(block("white", -1, n, 0), first); first = False
            time.sleep(0.035)
        for hot in range(_PRISM_N):        # phase 2: white beam runs down the edge
            draw(block("white", hot, _PRISM_N, 0), first)
            time.sleep(0.03)
        for wn in range(len(_SPLASH_WORD) + 1):  # phase 3: disperse + type wordmark
            draw(block("color", -1, _PRISM_N, wn), first)
            time.sleep(0.04)
        time.sleep(0.2)
    except KeyboardInterrupt:
        # Ctrl+C skips straight to the finished banner rather than aborting.
        try:
            draw(block("color", -1, _PRISM_N, len(_SPLASH_WORD)), first)
        except Exception:
            pass
    except Exception:
        pass  # decoration must never take the tool down
    finally:
        sys.stdout.write("\033[?25h")  # restore cursor
        sys.stdout.flush()


def _set_terminal_title(title):
    """Sets the terminal window/tab title via the standard OSC escape
    sequence. Unlike anything printed to the scrolling output, this is the
    one thing that actually stays visible the whole time a long-running
    `up` session is active, regardless of how much log output scrolls by."""
    if not _color_supported():
        return
    sys.stdout.write(f"\033]0;{title}\007")
    sys.stdout.flush()


def print_provider_banner(cfg):
    """Always shown right before an action command does anything against a
    cloud, so there's never ambiguity about which one is currently active
    -- especially now that switching between three is a normal thing to do.
    Also sets the terminal title to the same, which -- unlike this banner --
    stays visible for as long as the session runs, even once this scrolls
    off screen."""
    provider = rc.current_provider(cfg)
    label = PROVIDER_LABELS.get(provider, provider)
    line = "=" * 62
    print(_colorize(line, provider))
    print(_colorize(f" ACTIVE PROVIDER: {label}", provider))
    print(_colorize(line, provider))
    _set_terminal_title(f"{label} -- prism")


def main():
    parser = build_parser()
    args = parser.parse_args()
    # Startup animation, only for `up` -- the "launch the rotator" moment where a
    # long-lived session makes the banner worth it. The quick utility commands
    # (status/list/test/config/trust/...) stay instant instead of sitting through
    # it. Best-effort and TTY-only, so piped/scripted use (and the test suite)
    # never sees it; --no-banner or NO_COLOR / PRISM_NO_BANNER opt out.
    if args.command == "up" and not getattr(args, "no_banner", False):
        _launch_splash()
    # Check for a complete config the moment the tool launches, for every
    # command except `init` (owns its own create/overwrite flow) and
    # `status` (a read-only diagnostic -- it reports config state itself
    # and shouldn't have a side-effecting wizard sprung on it). If anything
    # is missing and we're attached to a real terminal, the wizard runs
    # right here, before the requested command does anything.
    if args.command not in ("init", "status", "config", "trust"):
        # Only `up` (fresh setup/deploy) should fall into the wizard when there's
        # no config. `down`/`list`/`test` act on an existing session, so a missing
        # config there means wrong directory -- get a clear pointer, not the wizard.
        cfg = ensure_config(allow_wizard=(args.command == "up"))
        if args.command in ("up", "down", "list", "test"):
            print_provider_banner(cfg)

    debug = getattr(args, "debug", False)
    if debug:
        args.func(args)
        return

    try:
        args.func(args)
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as exc:
        sys.exit(f"[!] {exc}\n    (re-run with --debug for the full traceback)")


if __name__ == "__main__":
    main()
