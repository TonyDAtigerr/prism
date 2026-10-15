"""
relay_common.py
-----------------
Pieces shared across all three provider backends (cloudflare_relay_manager.py
for Cloudflare, gcp_relay_manager.py, azure_relay_manager.py) and
rotator_addon.py: config/endpoints file paths and loading, relay-name-prefix
generation, and the canary test -- none of this talks to any specific
cloud's API, so it doesn't belong duplicated three times.

cloudflare_relay_manager.py re-exports these names for backwards
compatibility -- existing code that does `import cloudflare_relay_manager as
cfm` and references `cfm.CONFIG_PATH` / `cfm.load_config` etc. keeps working
unchanged.
"""

import json
import os
import random
import re
import string
import sys
from pathlib import Path

import requests

# Config + endpoints default to the current working directory, so each
# engagement folder keeps its own independent set of relays. Set PRISM_HOME to
# a directory to read/write them there instead -- so you can run `test`/`list`/
# `down` (or `up`) from anywhere (e.g. a tool's own folder) against one already
# deployed session, instead of having to cd back to where you ran `up`.
_PRISM_BASE = (
    Path(os.environ["PRISM_HOME"]).expanduser()
    if os.environ.get("PRISM_HOME")
    else Path(".")
)
CONFIG_PATH = _PRISM_BASE / "prism.json"
ENDPOINTS_PATH = _PRISM_BASE / "endpoints.json"

# --------------------------------------------------------------------------
# Command highlighting: make any shell command the tool tells the user to run
# stand out from the surrounding prose. Applied to help/hint/error text via
# highlight_commands() below, so a reader can spot "the thing to actually type"
# at a glance instead of hunting for the indented line.
_ANSI_RESET = "\033[0m"
_ANSI_CMD = "\033[1;36m"   # bold cyan -- the command itself
_ANSI_DIM = "\033[2m"      # dim -- trailing `# ...` explanatory comments

# First-token allowlist: an indented line is treated as a command only when it
# clearly starts one. This keeps wrapped prose continuations (e.g. a sentence
# that spills onto an indented next line) from being falsely highlighted.
_CMD_TOKENS = frozenset((
    "curl", "curl.exe", "wget", "sudo", "apt", "apt-get", "dpkg", "pip", "pip3",
    "pipx", "python", "python3", "py", "kill", "taskkill", "pkill", "which",
    "where", "az", "gcloud", "gsutil", "func", "wrangler", "npx", "npm", "brew",
    "proxychains", "proxychains4", "export", "set", "netstat", "findstr", "cd",
    "chmod", "chown", "ssh", "scp", "git", "mkfifo", "source", "bash", "sh",
    "zip", "unzip", "docker", "mitmdump", "prism", "echo", "printf", "cp",
    "mv", "rm", "ls", "cat",
))


def _supports_color():
    # Only emit escape codes to a real terminal, and honor the NO_COLOR
    # convention (https://no-color.org). Piped/redirected output would just
    # get literal escape characters instead of color.
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _looks_like_command(body):
    """True if `body` (an indented line with leading whitespace stripped)
    starts a command the user is meant to run."""
    if not body:
        return False
    first = body.split()[0]
    return (
        first in _CMD_TOKENS
        or first.startswith(("./", "$", "http://", "https://"))
    )


def highlight_commands(text):
    """Return `text` with runnable command lines made visually distinct: the
    command bold-cyan, any trailing `# comment` dimmed. Indentation is left
    exactly as-is so commands stay copy-paste-clean. A no-op (returns `text`
    unchanged) when stdout isn't a TTY or NO_COLOR is set, so nothing leaks
    into piped output."""
    if not _supports_color():
        return text
    out = []
    for line in text.split("\n"):
        m = re.match(r"^(\s{2,})(\S.*)$", line)
        if not m or not _looks_like_command(m.group(2)):
            out.append(line)
            continue
        indent, body = m.group(1), m.group(2)
        # Peel off a trailing "  # explanation" so it can be dimmed separately
        # from the command (a bare "#..." line is treated as all-comment).
        cmt = re.search(r"(\s+#.*)$", body)
        if cmt and not body.startswith("#"):
            code = body[: cmt.start()]
            out.append(f"{indent}{_ANSI_CMD}{code}{_ANSI_RESET}{_ANSI_DIM}{cmt.group(1)}{_ANSI_RESET}")
        else:
            out.append(f"{indent}{_ANSI_CMD}{body}{_ANSI_RESET}")
    return "\n".join(out)

PROVIDERS = ("cloudflare", "gcp", "azure")
PROVIDER_LABELS = {
    "cloudflare": "Cloudflare Workers",
    "gcp": "GCP Cloud Functions",
    "azure": "Azure Functions",
}


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"Missing {CONFIG_PATH}. Run `prism init`.")
    return json.loads(CONFIG_PATH.read_text())


def current_provider(cfg):
    return cfg.get("provider", "cloudflare")


def warn_if_wrong_backend(cfg, this_provider):
    """Each backend module (cloudflare_relay_manager.py / gcp_relay_manager.py /
    azure_relay_manager.py) is also runnable directly, standalone, for
    debugging -- but it ONLY ever talks to its own cloud, regardless of
    what prism.json's "provider" field currently says. Running
    the wrong one directly against a config set up for a different
    provider silently produces a misleading "no workers" result (querying
    an unrelated/empty account) rather than an error -- warn loudly rather
    than let that pass silently."""
    configured = current_provider(cfg)
    if configured == this_provider:
        return
    this_label = PROVIDER_LABELS[this_provider]
    configured_label = PROVIDER_LABELS.get(configured, configured)
    print(
        f"[!] Note: {CONFIG_PATH} is currently configured for '{configured}' "
        f"({configured_label}), not {this_label}. This command only ever talks to "
        f"{this_label} -- it will not see your active {configured_label} relays.\n"
        f"    If you meant to check/manage those, run `prism` "
        f"instead (it dispatches to whichever provider is actually configured).\n"
    )


# Pull a subscription id out of an Azure error so we can echo it back into the
# copy-pasteable `az` command we suggest (e.g. "The subscription 'c5f0...' is").
_SUBSCRIPTION_ID_RE = re.compile(r"subscription '([0-9A-Fa-f-]{8,})'")


def actionable_cli_hint(stderr):
    """Map a known, user-fixable cloud account state to concrete 'what to do /
    where to look' guidance, so a failed deploy tells the user how to recover
    instead of just echoing the provider's raw error. These states (disabled
    subscription, spending limit, billing not enabled) are account/billing
    problems the provider's own error never explains in plain terms. Returns
    '' when the error isn't one we have specific advice for, so the caller can
    append it unconditionally."""
    text = (stderr or "")
    low = text.lower()

    # Azure: subscription disabled or read-only -> no writes/creates allowed.
    if ("readonlydisabledsubscription" in low
            or "disabledsubscription" in low
            or ("subscription" in low and "is disabled" in low)):
        m = _SUBSCRIPTION_ID_RE.search(text)
        sub = m.group(1) if m else "<subscription-id>"
        return (
            "\n    -> Your Azure subscription is disabled or read-only, so nothing can be\n"
            "       created. This is an Azure billing/account state, not a Prism problem.\n"
            "       Usual causes: free trial or credit expired, spending limit reached, or\n"
            "       a past-due payment.\n"
            "       Where to look: portal.azure.com -> Subscriptions -> this subscription\n"
            "       -> Overview shows the reason and an 'Upgrade'/'Reactivate' button; or\n"
            "       Cost Management + Billing -> Payment methods to clear a spending limit\n"
            "       or settle a balance.\n"
            f"       Check its state:  az account subscription show --subscription-id {sub} \\\n"
            "                            --query \"{name:displayName,state:state}\" -o json\n"
            "       Or keep moving now: set \"provider\" to \"gcp\" or \"cloudflare\" in\n"
            "       prism.json and re-run (note: Cloudflare can't do TLS impersonation)."
        )

    # Azure: spending limit hit on its own (credit/free subscriptions).
    if "spending limit" in low:
        return (
            "\n    -> Your Azure subscription hit its spending limit, which blocks new\n"
            "       resource creation until the next billing cycle. Remove it at\n"
            "       portal.azure.com -> Subscriptions -> this one -> 'Remove spending\n"
            "       limit' (converts toward Pay-As-You-Go; needs a payment method)."
        )

    # GCP: billing not enabled/linked on the project.
    if "billing" in low and ("disabled" in low or "not enabled" in low
                             or "must be enabled" in low):
        return (
            "\n    -> Billing isn't enabled on this GCP project, so Cloud Functions can't\n"
            "       deploy. Enable it at console.cloud.google.com/billing -> link a\n"
            "       billing account to the project, then re-run. (Not a Prism problem.)"
        )

    return ""


def summarize_cli_error(stderr, limit=500):
    """Both `gcloud` and `az` put the human-readable summary at the START of
    their error output (gcloud: 'ERROR: (gcloud.<command>) <message>'; az:
    the error message itself, with structured JSON detail trailing it) --
    naively slicing the LAST `limit` characters of a long structured error
    (as gcp_relay_manager.py/azure_relay_manager.py used to) tends to land
    mid-field inside a details/YAML/JSON blob and print as garbled noise --
    a bare URL fragment, a mid-word cutoff -- instead of the actual message.
    Take from the start instead, where the real message lives, and mark it
    truncated when it is. For a handful of known account/billing states we
    also append concrete recovery steps (see actionable_cli_hint)."""
    text = (stderr or "").strip()
    if not text:
        return "(no error output)"
    summary = text[:limit] + ("..." if len(text) > limit else "")
    return summary + actionable_cli_hint(text)


def random_suffix(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def name_prefix(cfg):
    """The prefix every deployed relay's name starts with -- user-chosen or
    randomly generated at setup time (prism's wizard normally sets
    this). If it's still missing here (e.g. a backend module used directly
    with a hand-written config), generate one on the spot rather than
    falling back to a fixed brand string -- and cache it on cfg so every
    relay deployed in this run shares the same prefix instead of each
    getting its own."""
    if not cfg.get("relay_prefix"):
        # Neutral 'svc-' rather than 'relay-' so deployed resource names don't
        # advertise their purpose (matches cli.py's _random_relay_prefix).
        cfg["relay_prefix"] = f"svc-{random_suffix()}"
    return cfg["relay_prefix"]


def load_endpoints():
    return json.loads(ENDPOINTS_PATH.read_text()) if ENDPOINTS_PATH.exists() else []


def save_endpoints(endpoints):
    ENDPOINTS_PATH.write_text(json.dumps(endpoints, indent=2))


# Public TLS-fingerprint echo service used by `test --fingerprint`. The relay
# fetches this, so the JA3/JA4 it reports back is the fingerprint the RELAY
# presents to a target -- exactly what we want to verify. Any browser profile
# proves the relay honors X-Impersonate; chrome120 is a stable, known one.
FINGERPRINT_API = "https://tls.peet.ws/api/all"
FINGERPRINT_PROFILE = "chrome120"


def _parse_fingerprint(text):
    """Pull (ja3, ja4, user_agent) out of the fingerprint API's JSON, degrading
    gracefully if the service ever changes its shape."""
    try:
        d = json.loads(text)
        tls = d.get("tls") or {}
        return (tls.get("ja3_hash") or "?", tls.get("ja4") or "?", d.get("user_agent") or "?")
    except Exception:
        return ("(unparsed)", "(unparsed)", (text or "").strip()[:80])


def _test_fingerprints(cfg, endpoints):
    """Route a canary through each relay to a TLS-fingerprint echo service and
    print the JA3/JA4/UA the relay presents. This is the live check for the
    `impersonate` knob: with it on, GCP/Azure relays should report a real
    browser JA3/JA4; Cloudflare can't (fetch() has no TLS control)."""
    impersonate = bool(cfg.get("impersonate", False))
    print(f"Fingerprint check via {FINGERPRINT_API}")
    if impersonate:
        print(f"  impersonate=on (profile {FINGERPRINT_PROFILE}) -- GCP/Azure should show a "
              "real-browser JA3/JA4; Cloudflare stays the runtime's.")
    else:
        print("  impersonate=off -- every relay shows its runtime's own fingerprint. "
              "Enable `impersonate` in prism.json (+ `up --redeploy`) to change that.")
    for ep in endpoints:
        provider = ep.get("provider", "?")
        headers = {"X-Relay-Auth": cfg["auth_token"], "X-Target-URL": FINGERPRINT_API}
        if impersonate:
            headers["X-Impersonate"] = FINGERPRINT_PROFILE
        try:
            r = requests.get(ep["url"], headers=headers, timeout=25)
        except requests.RequestException as e:
            print(f"  {ep['url']} ({provider}): ERROR {e}")
            continue
        if r.status_code != 200:
            print(f"  {ep['url']} ({provider}): HTTP {r.status_code} -> {r.text.strip()[:160]}")
            continue
        ja3, ja4, ua = _parse_fingerprint(r.text)
        note = "  <- Cloudflare can't impersonate" if (impersonate and provider == "cloudflare") else ""
        print(f"  {ep['url']} ({provider}):{note}")
        print(f"      JA4 {ja4}")
        print(f"      JA3 {ja3}")
        print(f"      UA  {ua}")


def cmd_test(cfg, fingerprint=False):
    """Canary-test every tracked endpoint. Provider-agnostic -- it's just an
    HTTP request using the shared X-Relay-Auth / X-Target-URL protocol every
    relay (worker.js, gcp_relay_function, azure_relay_function) implements
    identically. With fingerprint=True, reports the JA3/JA4 each relay presents
    (see _test_fingerprints) instead of a plain reachability check."""
    if not ENDPOINTS_PATH.exists():
        sys.exit("There are currently no deployed workers -- run `prism up` first.")
    endpoints = load_endpoints()
    if not endpoints:
        print("There are currently no deployed workers.")
        return
    if fingerprint:
        _test_fingerprints(cfg, endpoints)
        return
    for ep in endpoints:
        try:
            r = requests.get(
                ep["url"],
                headers={
                    "X-Relay-Auth": cfg["auth_token"],
                    "X-Target-URL": "https://httpbin.org/ip",
                },
                timeout=20,
            )
            print(f"{ep['url']}: HTTP {r.status_code} -> {r.text.strip()[:200]}")
        except requests.RequestException as e:
            print(f"{ep['url']}: ERROR {e}")
