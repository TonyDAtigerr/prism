"""
gcp_relay_manager.py
----------------------
GCP Cloud Functions backend -- same job as cloudflare_relay_manager.py, but deploys
gcp_relay_function/ (a 2nd-gen HTTP Cloud Function implementing the exact
same X-Relay-Auth / X-Target-URL relay protocol as worker.js) instead of a
Cloudflare Worker. rotator_addon.py doesn't know or care which backend
deployed an endpoint -- it just uses whatever's in endpoints.json.

Deploys via the `gcloud` CLI (shelled out, not the raw REST API) -- the
same reasoning as wrangler.toml existing alongside cloudflare_relay_manager.py's
raw API calls: Google's own maintained CLI handles auth, retries, and API
version changes far more reliably than reimplementing this from scratch.

Prerequisites (see README's "GCP Cloud Functions setup" for the full walk-
through prism's wizard gives you):
    - gcloud CLI installed and on PATH: https://cloud.google.com/sdk/docs/install
    - Already authenticated: `gcloud auth login`
    - A billing account on the GCP account somewhere (doesn't need to be
      linked to gcp_project_id ahead of time -- see below)

_ensure_project() automatically creates gcp_project_id if it doesn't exist
yet (like _ensure_resource_group() does for Azure), and _ensure_apis_enabled()
auto-enables the Cloud Functions/Cloud Build/Cloud Run/Artifact Registry APIs
a gen2 function needs -- no manual `gcloud projects create` or `gcloud
services enable` needed. The one thing that CANNOT be automated: a brand-new
project has no billing account linked, and enabling those APIs (or deploying
to them) fails outright without one. If that happens, the error is
surfaced with the exact commands to link one (`gcloud billing accounts
list` then `gcloud billing projects link`).

Config fields this backend reads from prism.json:
    "gcp_project_id": "<GCP project ID>"
    "gcp_region": "<region, e.g. us-central1>"

Usage (normally driven through prism, not run directly):
    python3 gcp_relay_manager.py create --count 6
    python3 gcp_relay_manager.py list
    python3 gcp_relay_manager.py test
    python3 gcp_relay_manager.py cleanup
"""

import argparse
import shutil
import subprocess
import sys
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

FUNCTION_SOURCE_DIR = Path(__file__).resolve().parent / "gcp_relay_function"
RUNTIME = "python312"
ENTRY_POINT = "relay"

# gen2 Cloud Functions run on Cloud Run under the hood, hence the extra two
# beyond Cloud Functions itself.
REQUIRED_APIS = (
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
)


def find_gcloud():
    return shutil.which("gcloud")


def _require_gcloud():
    gcloud = find_gcloud()
    if not gcloud:
        if sys.platform in ("linux", "darwin"):
            # Google's own official interactive installer script -- works
            # the same way on both Linux and macOS.
            install_hint = (
                "Install it:\n"
                "    curl -sSL https://sdk.cloud.google.com | bash\n"
                "\n"
                "Package-manager alternatives (apt/dnf/etc.):\n"
                "    https://cloud.google.com/sdk/docs/install"
            )
        else:
            install_hint = (
                "Install it:\n"
                "    https://cloud.google.com/sdk/docs/install"
            )
        sys.exit(highlight_commands(
            "gcloud CLI not found on PATH.\n"
            "\n"
            f"{install_hint}\n"
            "\n"
            "Then authenticate once before retrying:\n"
            "    gcloud auth login\n"
            "    gcloud config set project <your-project-id>"
        ))
    return gcloud


def _run(args, **kwargs):
    """subprocess.run with --quiet auto-injected so nothing blocks on an
    interactive Y/N prompt (there's no TTY for gcloud to prompt against when
    called from here)."""
    gcloud = _require_gcloud()
    full_args = [gcloud] + args
    if "--quiet" not in full_args:
        full_args.append("--quiet")
    return subprocess.run(full_args, capture_output=True, text=True, **kwargs)


def _project_exists(project):
    # `gcloud projects describe` is the standard existence check -- succeeds
    # only if the project exists AND the current login can see it.
    return _run(["projects", "describe", project]).returncode == 0


def _ensure_project(cfg):
    """Create gcp_project_id if it doesn't exist yet -- mirrors
    azure_relay_manager.py's _ensure_resource_group(). Idempotent (the
    existence check makes repeat calls cheap), and self-contained the same
    way deploy_one() is, so rotator_addon.py's burn policy (which calls
    deploy_one() directly for a single on-demand replacement) doesn't need
    its own copy of this logic."""
    project = cfg["gcp_project_id"]
    if _project_exists(project):
        return True
    print(f"[*] GCP project '{project}' doesn't exist yet -- creating it ...")
    create = _run(["projects", "create", project, "--name", project])
    if create.returncode != 0:
        print(f"[!] Failed to create project {project}: {summarize_cli_error(create.stderr)}")
        print(
            "    Project IDs are globally unique across ALL of GCP (like a domain name) -- "
            "if that's the failure, pick a different gcp_project_id (re-run `init --force`, "
            "or `init --provider gcp` to just update that one field) and try again."
        )
        return False
    print(f"[+] Created project {project}.")
    return True


def _ensure_apis_enabled(cfg):
    """Enable the APIs a gen2 Cloud Function deploy needs. A brand-new
    project has none of these enabled, and (unlike Azure's resource
    provider registration) this step also needs a billing account linked --
    that part genuinely can't be automated blind, so surface a clear next
    step rather than a bare gcloud error if it's the cause."""
    project = cfg["gcp_project_id"]
    enable = _run(["services", "enable", *REQUIRED_APIS, "--project", project])
    if enable.returncode == 0:
        return True
    stderr = enable.stderr.strip()
    if "billing" in stderr.lower():
        # A billing-not-linked failure comes back as a long structured
        # JSON/YAML error blob -- truncating it to the last N chars (as the
        # generic branch below does, to keep unrelated errors short) tends
        # to land mid-string here and print as garbled noise (e.g. a bare
        # "7&services=..." query-string fragment) instead of anything
        # readable. Skip the raw dump entirely for this one known cause and
        # just give the actionable fix -- nothing in that blob adds
        # information beyond "billing isn't linked".
        print(f"[!] Failed to enable required APIs on {project}: no billing account linked.")
        print(
            "    A brand-new project has no billing account attached, and Cloud Functions "
            "(gen2, billed via Cloud Run) requires one even within the free tier. Link one:\n"
            "      gcloud billing accounts list\n"
            f"      gcloud billing projects link {project} --billing-account=<ACCOUNT_ID>\n"
            "    Then re-run `up` -- it picks up from here."
        )
    else:
        print(f"[!] Failed to enable required APIs on {project}: {summarize_cli_error(stderr)}")
    return False


def deploy_one(cfg, name):
    """Deploy one relay Cloud Function. Returns the function's URL, or None
    on failure (prints the gcloud error output either way). Self-contained --
    ensures the project exists and required APIs are enabled first (idempotent,
    cheap if already done), same reasoning as azure_relay_manager.deploy_one()."""
    if not _ensure_project(cfg):
        return None
    if not _ensure_apis_enabled(cfg):
        return None

    project = cfg["gcp_project_id"]
    region = cfg.get("gcp_region", "us-central1")

    deploy = _run([
        "functions", "deploy", name,
        "--gen2",
        f"--project={project}",
        f"--region={region}",
        f"--runtime={RUNTIME}",
        f"--source={FUNCTION_SOURCE_DIR}",
        f"--entry-point={ENTRY_POINT}",
        "--trigger-http",
        "--allow-unauthenticated",
        f"--set-env-vars=RELAY_AUTH_TOKEN={cfg['auth_token']}",
    ])
    if deploy.returncode != 0:
        print(f"[!] Deploy failed for {name}: {summarize_cli_error(deploy.stderr)}")
        return None

    # NB: unlike `deploy` (--gen2), `describe` and `list` take --v2 instead
    # -- confirmed against `gcloud functions describe/list --help` directly,
    # not assumed; the flag name is NOT consistent across subcommands.
    describe = _run([
        "functions", "describe", name,
        "--v2",
        f"--project={project}",
        f"--region={region}",
        "--format=value(serviceConfig.uri)",
    ])
    url = describe.stdout.strip()
    if describe.returncode != 0 or not url:
        print(f"[!] {name} deployed but couldn't retrieve its URL: {summarize_cli_error(describe.stderr)}")
        return None
    return url


# Uniform interface every backend exposes (cloudflare_relay_manager.py's deploy_one
# needs an extra worker_source arg, so it wraps its own deploy_one() under
# this name instead) -- used by both cmd_create and rotator_addon.py's burn
# policy for a single on-demand replacement.
deploy_one_relay = deploy_one


def cmd_create(cfg, count):
    _require_gcloud()
    if not _ensure_project(cfg):
        return
    if not _ensure_apis_enabled(cfg):
        return

    existing = load_endpoints()
    created = []
    for _ in range(count):
        name = f"{name_prefix(cfg)}-{random_suffix()}"
        print(f"[*] Deploying {name} (this can take a minute or two on GCP) ...")
        url = deploy_one(cfg, name)
        if url:
            created.append({"name": name, "url": url, "provider": "gcp"})
            print(f"    -> {url}")
        else:
            print("    -> failed, skipping")
    all_endpoints = existing + created
    save_endpoints(all_endpoints)
    print(f"\n[+] {len(created)} endpoint(s) created, {len(all_endpoints)} total in {ENDPOINTS_PATH}")


def _our_functions(cfg):
    """Function names on this project/region that belong to us: anything
    endpoints.json is tracking by exact name, plus anything matching the
    *current* prefix that isn't tracked locally."""
    region = cfg.get("gcp_region", "us-central1")
    listing = _run([
        "functions", "list",
        "--v2",
        f"--project={cfg['gcp_project_id']}",
        f"--regions={region}",
        "--format=value(name)",
    ])
    if listing.returncode != 0:
        print(f"[!] Couldn't list functions: {summarize_cli_error(listing.stderr)}")
        if "SERVICE_DISABLED" in listing.stderr:
            # The most common way to land here: an earlier `up` failed to
            # enable the Cloud Functions API because billing wasn't linked
            # yet (see _ensure_apis_enabled) -- so there was never anything
            # deployed in the first place, and this isn't a new problem.
            print(
                "    The Cloud Functions API isn't enabled on this project -- most likely "
                "because an earlier `up` never got past linking a billing account (see "
                "README's 'Have a billing account linked' step). Nothing was ever "
                "deployed if so; link billing and run `up` again rather than troubleshooting "
                "this as a separate issue."
            )
        return []
    # `name` can come back as a bare name or a full resource path
    # (projects/.../locations/.../functions/NAME) depending on gcloud
    # version -- always take the last path segment.
    all_names = {line.strip().split("/")[-1] for line in listing.stdout.splitlines() if line.strip()}

    tracked = {ep["name"] for ep in load_endpoints() if ep.get("provider") == "gcp"}
    prefix = name_prefix(cfg)
    return sorted((tracked | {n for n in all_names if n.startswith(prefix)}) & all_names)


def cmd_list(cfg):
    _require_gcloud()
    names = _our_functions(cfg)
    if not names:
        print("There are currently no deployed GCP Cloud Functions.")
        return
    for n in names:
        print(n)


def delete_one(cfg, name):
    # `gcloud functions delete` has no --gen2/--v2 flag at all (confirmed
    # against --help) -- it resolves gen1 vs gen2 automatically.
    region = cfg.get("gcp_region", "us-central1")
    d = _run([
        "functions", "delete", name,
        f"--project={cfg['gcp_project_id']}",
        f"--region={region}",
    ])
    return d.returncode == 0


def cmd_cleanup(cfg):
    _require_gcloud()
    names = _our_functions(cfg)
    if not names:
        print("There are currently no deployed GCP Cloud Functions.")
    for name in names:
        status = "deleted" if delete_one(cfg, name) else "FAILED"
        print(f"{name}: {status}")
    if ENDPOINTS_PATH.exists():
        ENDPOINTS_PATH.unlink()
        print(f"Removed {ENDPOINTS_PATH}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Deploy N new relay Cloud Functions")
    p_create.add_argument("--count", type=int, default=3)

    sub.add_parser("list", help="List relay Cloud Functions in this project/region")
    sub.add_parser("test", help="Send a canary request through every endpoint")
    sub.add_parser("cleanup", help="Delete every relay Cloud Function this tool created")

    args = parser.parse_args()
    cfg = load_config()
    warn_if_wrong_backend(cfg, "gcp")

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
