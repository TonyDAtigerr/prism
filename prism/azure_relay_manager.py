"""
azure_relay_manager.py
------------------------
Azure Functions backend -- same job as cloudflare_relay_manager.py, but deploys
azure_relay_function/ (a Python v2-model HTTP function implementing the
exact same X-Relay-Auth / X-Target-URL relay protocol as worker.js)
instead of a Cloudflare Worker. rotator_addon.py doesn't know or care
which backend deployed an endpoint -- it just uses whatever's in
endpoints.json.

Deploys via the `az` CLI (shelled out) -- same reasoning as the GCP
backend using `gcloud`: Microsoft's own maintained CLI handles auth and
API-version churn far more reliably than reimplementing the ARM/Kudu APIs
from scratch. Code is pushed with a zip-deploy (`az functionapp
deployment source config-zip`), which needs no extra tooling beyond `az`
itself and Python's stdlib zipfile -- deliberately avoiding a dependency
on the separate Azure Functions Core Tools (`func`).

Prerequisites (see README's "Azure Functions setup" for the full walk-
through prism's wizard gives you):
    - az CLI installed and on PATH: https://learn.microsoft.com/cli/azure/install-azure-cli
    - Already authenticated: `az login`
    - An actual Azure subscription attached to that login (a bare tenant with no
      subscription won't work -- see README's "tenant vs. subscription" note)

_ensure_providers_registered() automatically checks and registers the
Microsoft.Web and Microsoft.Storage resource providers on first deploy if
they aren't already (one-time per subscription, can take a minute) -- no
manual `az provider register` needed. Without this, a brand-new
subscription's missing Microsoft.Storage registration produces a badly
misleading error: `az storage account create` fails with
"(SubscriptionNotFound) Subscription <id> was not found" even though the
subscription is completely valid.

Config fields this backend reads from prism.json:
    "azure_resource_group": "<resource group name -- created if it doesn't exist>"
    "azure_storage_account": "<storage account name -- lowercase letters/digits
                                only, 3-24 chars, globally unique; created if
                                it doesn't exist; shared across every relay>"
    "azure_region": "<region, e.g. eastus>"

Usage (normally driven through prism, not run directly):
    python3 azure_relay_manager.py create --count 6
    python3 azure_relay_manager.py list
    python3 azure_relay_manager.py test
    python3 azure_relay_manager.py cleanup
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from prism.relay_common import (
    ENDPOINTS_PATH,
    load_config,
    load_endpoints,
    name_prefix,
    random_suffix,
    save_endpoints,
    cmd_test,
    highlight_commands,
    summarize_cli_error,
    warn_if_wrong_backend,
)

FUNCTION_SOURCE_DIR = Path(__file__).resolve().parent / "azure_relay_function"
PYTHON_RUNTIME_VERSION = "3.11"


def find_az():
    return shutil.which("az")


# Cache so the health check below only actually runs once per process,
# not on every single _run() call (dozens per deploy) -- it's cheap, but
# not free, and only needs to catch a broken install once, early.
_az_health_checked = False


def _az_health_check(az):
    """Catch a broken az CLI install with one cheap `az version` call,
    before a real deploy sinks minutes into resource provider registration
    only to crash confusingly partway through. A distro-packaged az CLI
    (e.g. `apt install azure-cli` from a Linux distro's own default repo,
    as opposed to Microsoft's official apt repo/installer script) is a
    known source of internal crashes -- installed into system Python
    site-packages, it picks up version-mismatched dependencies and throws
    things like `'NoneType' object is not callable` deep inside its own
    knack/azure.cli.core code, not a normal az error message. The tell is
    a Python traceback in the output where a real az error would never put
    one.

    Confirmed against a live crash with this exact signature, on Kali
    specifically -- and confirmed the naive fix (`apt remove` + re-run
    Microsoft's installer with no DIST_CODE) doesn't actually work there:
    Microsoft's installer doesn't recognize Kali's `kali-rolling` codename,
    fails silently, and falls back to suggesting `sudo apt install
    azure-cli` -- which reinstalls the exact same broken distro package,
    undoing the removal with no visible sign anything went wrong. The fix
    message below is written specifically to walk around that trap, not
    just point at the installer generically."""
    result = subprocess.run([az, "version", "--output", "json"], capture_output=True, text=True)
    if _looks_like_broken_az(result):
        _exit_az_broken()


# The traceback a crashing az prints. A real az error -- even a fatal one --
# never contains one, so this is an unambiguous signature.
_AZ_CRASH_MARKER = "Traceback (most recent call last):"


def _looks_like_broken_az(result):
    """True if this completed az call crashed internally rather than failing
    the way a real az error does."""
    if result.returncode == 0:
        return False
    return _AZ_CRASH_MARKER in ((result.stdout or "") + (result.stderr or ""))


# The one install recipe that actually works on Debian/Kali/sid. Those distros
# ship their own azure-cli built against the *system* Python (which Azure CLI
# doesn't support -> it crashes on launch) AND give it a higher version number
# than Microsoft's repo -- so a plain `apt install`, and even the aka.ms
# convenience script, keep the broken package ("already newest") instead of
# installing Microsoft's. We purge it, add Microsoft's repo, and PIN that repo
# so Microsoft's bundled-Python build installs despite its lower version. One
# copy-paste block, safe to run whether or not a distro azure-cli is present.
_AZ_DEBIAN_FIX = (
    "    sudo apt remove --purge azure-cli -y\n"
    "    sudo mkdir -p /etc/apt/keyrings\n"
    "    curl -sLS https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg\n"
    "    sudo chmod go+r /etc/apt/keyrings/microsoft.gpg\n"
    "    echo \"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ bookworm main\" | sudo tee /etc/apt/sources.list.d/azure-cli.list\n"
    "    printf 'Package: azure-cli\\nPin: origin packages.microsoft.com\\nPin-Priority: 1001\\n' | sudo tee /etc/apt/preferences.d/azure-cli\n"
    "    sudo apt-get update && sudo apt-get install -y azure-cli --allow-downgrades"
)


def _exit_az_broken():
    sys.exit(highlight_commands(
        "az CLI is installed but broken -- it crashes with a Python traceback instead\n"
        "of running. This is a Kali/Debian-sid packaging problem, not this tool: their\n"
        "azure-cli runs on the system Python, which Azure CLI doesn't support. Microsoft's\n"
        "own build bundles a working Python -- but the distro's package has a higher version\n"
        "number, so it blocks Microsoft's until you remove it and pin the repo.\n"
        "\n"
        "Copy-paste this whole block, then retry:\n"
        f"{_AZ_DEBIAN_FIX}\n"
        "\n"
        "Confirm it runs cleanly before retrying `up`:\n"
        "    az --version    # prints a version table, no Python traceback\n"
        "\n"
        "Still crashing afterward? Run Azure CLI from Microsoft's container instead:\n"
        "    https://learn.microsoft.com/cli/azure/run-azure-cli-docker"
    ))


def _require_az():
    az = find_az()
    if not az:
        if sys.platform == "linux":
            install_hint = (
                "Install Microsoft's build. On Debian/Ubuntu/Kali, copy-paste this whole\n"
                "block -- it removes any distro azure-cli, adds Microsoft's repo, and pins\n"
                "it so Microsoft's bundled-Python build installs (the distro package runs on\n"
                "the system Python, which Azure CLI doesn't support, and can outrank the repo):\n"
                f"{_AZ_DEBIAN_FIX}\n"
                "\n"
                "Confirm it runs cleanly:\n"
                "    az --version    # version table, no Python traceback\n"
                "\n"
                "Other distros (Fedora/RHEL/etc.):\n"
                "    https://learn.microsoft.com/cli/azure/install-azure-cli-linux"
            )
        elif sys.platform == "darwin":
            install_hint = (
                "Install it:\n"
                "    brew update && brew install azure-cli\n"
                "\n"
                "Details:\n"
                "    https://learn.microsoft.com/cli/azure/install-azure-cli-macos"
            )
        else:
            install_hint = (
                "Install it:\n"
                "    https://learn.microsoft.com/cli/azure/install-azure-cli"
            )
        sys.exit(highlight_commands(
            "az CLI not found on PATH.\n"
            "\n"
            f"{install_hint}\n"
            "\n"
            "Then run `az login` once before retrying."
        ))

    global _az_health_checked
    if not _az_health_checked:
        _az_health_checked = True
        _az_health_check(az)
    return az


def _run(args, **kwargs):
    az = _require_az()
    result = subprocess.run([az] + args + ["--output", "json"], capture_output=True, text=True, **kwargs)
    # The up-front `az version` probe in _az_health_check() is necessary but
    # not sufficient: a distro-packaged az can pass it and still crash on a
    # real command, because `version` doesn't import the command modules
    # where the dependency mismatch actually lives. Confirmed on Kali --
    # `az version` and `az provider register` both succeeded, then
    # `az group create` crashed. So re-check every call: without this, the
    # crash surfaces as a truncated traceback under some unrelated caller's
    # "[!] Failed to ..." line, and the fix instructions never print.
    if _looks_like_broken_az(result):
        _exit_az_broken()
    return result


def _exists(check_args):
    """True if an `az ... show`-style command succeeds (resource exists)."""
    r = _run(check_args)
    return r.returncode == 0


# Both required for this tool: Microsoft.Web for the Function App itself,
# Microsoft.Storage for its backing storage account. A brand-new
# subscription (e.g. a fresh Free Trial) commonly has neither registered
# yet, and the resulting error is badly misleading -- `az storage account
# create` fails with "(SubscriptionNotFound) Subscription <id> was not
# found" even though the subscription is completely valid; the real cause
# is just an unregistered resource provider. Confirmed against a Microsoft
# staff answer on this exact error, not guessed.
REQUIRED_PROVIDERS = ("Microsoft.Web", "Microsoft.Storage")


def _ensure_providers_registered(cfg):
    for namespace in REQUIRED_PROVIDERS:
        # NB: _run() always appends --output json regardless of what's passed
        # in args, so parse the result as JSON (a quoted string like
        # "Registered") rather than assuming a bare/tsv value.
        check = _run(["provider", "show", "--namespace", namespace, "--query", "registrationState"])
        try:
            state = json.loads(check.stdout.strip()) if check.stdout.strip() else None
        except ValueError:
            state = None
        if state == "Registered":
            continue
        print(f"[*] Registering the {namespace} resource provider on this subscription (one-time, can take a minute) ...")
        reg = _run(["provider", "register", "--namespace", namespace, "--wait"])
        if reg.returncode != 0:
            print(f"[!] Failed to register {namespace}: {summarize_cli_error(reg.stderr)}")
            return False
    return True


def _ensure_resource_group(cfg):
    rg = cfg["azure_resource_group"]
    region = cfg.get("azure_region", "eastus")
    if _exists(["group", "show", "--name", rg]):
        return True
    print(f"[*] Creating resource group {rg} in {region} ...")
    r = _run(["group", "create", "--name", rg, "--location", region])
    if r.returncode != 0:
        print(f"[!] Failed to create resource group {rg}: {summarize_cli_error(r.stderr)}")
        return False
    return True


def _ensure_storage_account(cfg):
    rg = cfg["azure_resource_group"]
    account = cfg["azure_storage_account"]
    region = cfg.get("azure_region", "eastus")
    if _exists(["storage", "account", "show", "--name", account, "--resource-group", rg]):
        return True
    print(f"[*] Creating storage account {account} (this can take a minute) ...")
    r = _run([
        "storage", "account", "create",
        "--name", account,
        "--resource-group", rg,
        "--location", region,
        "--sku", "Standard_LRS",
    ])
    if r.returncode != 0:
        print(f"[!] Failed to create storage account {account}: {summarize_cli_error(r.stderr)}")
        return False
    return True


def _build_zip():
    """Zip azure_relay_function/'s contents (not the parent folder itself --
    host.json must land at the zip root) into a temp file. Caller deletes it."""
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in FUNCTION_SOURCE_DIR.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(FUNCTION_SOURCE_DIR))
    return Path(tmp.name)


def deploy_one(cfg, name):
    """Deploy one relay Function App. Returns its URL, or None on failure.
    Self-contained -- ensures the required resource providers are
    registered and the resource group/storage account exist first
    (idempotent, cheap if already done) rather than assuming a prior
    cmd_create() already did it, since rotator_addon.py's burn policy calls
    this directly for a single on-demand replacement."""
    if not _ensure_providers_registered(cfg):
        return None
    if not _ensure_resource_group(cfg):
        return None
    if not _ensure_storage_account(cfg):
        return None

    rg = cfg["azure_resource_group"]
    region = cfg.get("azure_region", "eastus")
    storage = cfg["azure_storage_account"]

    create = _run([
        "functionapp", "create",
        "--resource-group", rg,
        "--consumption-plan-location", region,
        "--runtime", "python",
        "--runtime-version", PYTHON_RUNTIME_VERSION,
        "--functions-version", "4",
        "--os-type", "Linux",
        "--name", name,
        "--storage-account", storage,
    ])
    if create.returncode != 0:
        print(f"[!] Create failed for {name}: {summarize_cli_error(create.stderr)}")
        return None

    settings = _run([
        "functionapp", "config", "appsettings", "set",
        "--name", name,
        "--resource-group", rg,
        "--settings",
        f"RELAY_AUTH_TOKEN={cfg['auth_token']}",
        "SCM_DO_BUILD_DURING_DEPLOYMENT=true",
    ])
    if settings.returncode != 0:
        print(f"[!] {name} created but setting app config failed: {summarize_cli_error(settings.stderr)}")
        return None

    zip_path = _build_zip()
    try:
        deploy = _run([
            "functionapp", "deployment", "source", "config-zip",
            "--resource-group", rg,
            "--name", name,
            "--src", str(zip_path),
            "--build-remote", "true",
        ])
    finally:
        zip_path.unlink(missing_ok=True)

    if deploy.returncode != 0:
        print(f"[!] {name} created but code deploy failed: {summarize_cli_error(deploy.stderr)}")
        return None

    return f"https://{name}.azurewebsites.net/api/relay"


# Uniform interface every backend exposes (cloudflare_relay_manager.py's deploy_one
# needs an extra worker_source arg, so it wraps its own deploy_one() under
# this name instead) -- used by both cmd_create and rotator_addon.py's burn
# policy for a single on-demand replacement.
deploy_one_relay = deploy_one


def cmd_create(cfg, count):
    _require_az()
    if not _ensure_providers_registered(cfg):
        return
    if not _ensure_resource_group(cfg):
        return
    if not _ensure_storage_account(cfg):
        return

    existing = load_endpoints()
    created = []
    for _ in range(count):
        name = f"{name_prefix(cfg)}-{random_suffix()}"
        print(f"[*] Deploying {name} (function app create + zip deploy, a few minutes) ...")
        url = deploy_one(cfg, name)
        if url:
            created.append({"name": name, "url": url, "provider": "azure"})
            print(f"    -> {url}")
        else:
            print("    -> failed, skipping")
    all_endpoints = existing + created
    save_endpoints(all_endpoints)
    print(f"\n[+] {len(created)} endpoint(s) created, {len(all_endpoints)} total in {ENDPOINTS_PATH}")


def _our_function_apps(cfg):
    """Function app names in this resource group that belong to us: anything
    endpoints.json is tracking by exact name, plus anything matching the
    *current* prefix that isn't tracked locally."""
    listing = _run([
        "functionapp", "list",
        "--resource-group", cfg["azure_resource_group"],
        "--query", "[].name",
    ])
    if listing.returncode != 0:
        print(f"[!] Couldn't list function apps: {summarize_cli_error(listing.stderr)}")
        return []
    try:
        all_names = set(json.loads(listing.stdout))
    except ValueError:
        all_names = set()

    tracked = {ep["name"] for ep in load_endpoints() if ep.get("provider") == "azure"}
    prefix = name_prefix(cfg)
    return sorted((tracked | {n for n in all_names if n.startswith(prefix)}) & all_names)


def cmd_list(cfg):
    _require_az()
    names = _our_function_apps(cfg)
    if not names:
        print("There are currently no deployed Azure Functions.")
        return
    for n in names:
        print(n)


def delete_one(cfg, name):
    d = _run(["functionapp", "delete", "--name", name, "--resource-group", cfg["azure_resource_group"]])
    return d.returncode == 0


def cmd_cleanup(cfg):
    _require_az()
    names = _our_function_apps(cfg)
    if not names:
        print("There are currently no deployed Azure Functions.")
    for name in names:
        status = "deleted" if delete_one(cfg, name) else "FAILED"
        print(f"{name}: {status}")
    if ENDPOINTS_PATH.exists():
        ENDPOINTS_PATH.unlink()
        print(f"Removed {ENDPOINTS_PATH}")
    print(
        "Note: the resource group and storage account are left in place (they're "
        "shared infrastructure, not per-relay) -- delete them yourself via the "
        "Azure Portal or `az group delete` if you're done with this project entirely, "
        "or run `prism down --purge-infra` for an interactive picker."
    )


def _list_resource_groups():
    """Every resource group on the current subscription -- not just the one
    the active config points at. Users accumulate more than one over time
    (a different azure_resource_group per engagement, or leftovers from
    manual testing), so a purge tool that only looked at the configured
    one would miss most of what someone actually wants to see."""
    listing = _run(["group", "list", "--query", "[].{name:name, location:location}"])
    if listing.returncode != 0:
        print(f"[!] Couldn't list resource groups: {summarize_cli_error(listing.stderr)}")
        return []
    try:
        return json.loads(listing.stdout)
    except ValueError:
        return []


def _list_storage_accounts():
    """Every storage account on the subscription, tagged with which
    resource group each lives in (needed for the delete call, and for
    skipping accounts whose whole resource group just got deleted above)."""
    listing = _run([
        "storage", "account", "list",
        "--query", "[].{name:name, resourceGroup:resourceGroup, location:location}",
    ])
    if listing.returncode != 0:
        print(f"[!] Couldn't list storage accounts: {summarize_cli_error(listing.stderr)}")
        return []
    try:
        return json.loads(listing.stdout)
    except ValueError:
        return []


def _resolve_picks(raw, items):
    """Parse a space/comma-separated selection against a numbered list of
    {"name": ...} dicts, accepting either the number shown next to an item
    or its exact name typed directly -- scanning a short numbered list is
    fast, but typing a name is faster once you already know what you want,
    e.g. the resource group or storage account you just typed into
    `init`. Returns the matched names; prints and skips anything that
    matches neither."""
    by_index = {i: item["name"] for i, item in enumerate(items, 1)}
    known = {item["name"] for item in items}
    picks = []
    for tok in raw.replace(",", " ").split():
        if tok.isdigit() and int(tok) in by_index:
            picks.append(by_index[int(tok)])
        elif tok in known:
            picks.append(tok)
        else:
            print(f"  Ignoring invalid selection: {tok}")
    return picks


def cmd_purge_infra(cfg):
    """Interactive picker for deleting resource groups and/or individual
    storage accounts, outside the normal relay-teardown path. Deleting a
    resource group cascades to everything inside it (storage account
    included); deleting a storage account on its own leaves the resource
    group and anything else in it intact -- offered separately so cleaning
    up one stray storage account doesn't force taking the whole group with
    it. Never runs automatically, and neither kind of deletion happens
    without the user typing the exact name back as confirmation -- a
    fat-fingered selection here is a lot more expensive than a wrong
    answer to a plain y/N prompt would be."""
    _require_az()

    if not sys.stdin.isatty():
        print("No terminal to prompt on -- run this interactively to select what to delete.")
        return

    deleted_groups = set()

    groups = _list_resource_groups()
    if not groups:
        print("No resource groups found on this subscription (or couldn't list them).")
    else:
        print("\nResource groups on this subscription:")
        configured_rg = cfg.get("azure_resource_group")
        for i, g in enumerate(groups, 1):
            marker = "  <- currently configured" if g["name"] == configured_rg else ""
            print(f"  {i}. {g['name']}  ({g['location']}){marker}")

        raw = input(
            "\nDelete which resource group(s)? Enter number(s), name(s), or a mix "
            "(space/comma separated), or Enter to skip: "
        ).strip()
        picks = _resolve_picks(raw, groups) if raw else []
        if raw and not picks:
            print("  Nothing matched -- skipping resource group deletion.")
        for g in picks:
            confirm = input(
                f"\nThis deletes '{g}' and EVERYTHING inside it -- storage accounts, "
                f"anything else you've put there, not just relay-related resources. "
                f"Type the resource group name to confirm: "
            ).strip()
            if confirm != g:
                print(f"  Skipped {g} (typed name didn't match).")
                continue
            print(f"[*] Deleting {g} (runs in the background -- can take several minutes)...")
            d = _run(["group", "delete", "--name", g, "--yes", "--no-wait"])
            if d.returncode == 0:
                print(f"  {g}: delete started -- check the Azure Portal to confirm when it finishes.")
                deleted_groups.add(g)
            else:
                print(f"  {g}: FAILED to start -- {summarize_cli_error(d.stderr)}")

    accounts = [a for a in _list_storage_accounts() if a.get("resourceGroup") not in deleted_groups]
    if not accounts:
        return

    print("\nStorage accounts on this subscription (excluding any in a resource group just deleted above):")
    configured_sa = cfg.get("azure_storage_account")
    for i, a in enumerate(accounts, 1):
        marker = "  <- currently configured" if a["name"] == configured_sa else ""
        print(f"  {i}. {a['name']}  (in '{a['resourceGroup']}', {a['location']}){marker}")

    raw = input(
        "\nDelete which storage account(s) individually (keeps their resource group and "
        "everything else in it)? Enter number(s), name(s), or a mix, or Enter to skip: "
    ).strip()
    picks = _resolve_picks(raw, accounts) if raw else []
    if raw and not picks:
        print("  Nothing matched -- skipping storage account deletion.")
    for name in picks:
        acct = next(a for a in accounts if a["name"] == name)
        confirm = input(
            f"\nThis permanently deletes storage account '{name}' (in resource group "
            f"'{acct['resourceGroup']}') and all data in it. Type the storage account "
            f"name to confirm: "
        ).strip()
        if confirm != name:
            print(f"  Skipped {name} (typed name didn't match).")
            continue
        print(f"[*] Deleting storage account {name} ...")
        d = _run([
            "storage", "account", "delete",
            "--name", name, "--resource-group", acct["resourceGroup"], "--yes",
        ])
        if d.returncode == 0:
            print(f"  {name}: deleted.")
        else:
            print(f"  {name}: FAILED -- {summarize_cli_error(d.stderr)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Deploy N new relay Function Apps")
    p_create.add_argument("--count", type=int, default=3)

    sub.add_parser("list", help="List relay Function Apps in this resource group")
    sub.add_parser("test", help="Send a canary request through every endpoint")
    sub.add_parser("cleanup", help="Delete every relay Function App this tool created")

    args = parser.parse_args()
    cfg = load_config()
    warn_if_wrong_backend(cfg, "azure")

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
