#!/usr/bin/env python3
"""
Offline test cases for the features added in the impersonation/opsec pass:

  - rotator `impersonate` knob      -> parsed, coherent per-session profile pick
  - rotator `upstream_proxy` knob   -> parsed, passed to the httpx client
  - relay `_fetch` (GCP + Azure)    -> curl_cffi impersonation, identity-header
                                       stripping, unknown-profile fallback
  - worker.js                       -> strips the X-Impersonate control header

They stub the heavy deps (httpx, mitmproxy, curl_cffi, functions_framework,
azure.functions) so nothing hits the network or a cloud, and exercise the real
module code. Run directly:  `python tests/test_new_features.py`  (exit 0 = all
passed). The live end-to-end check (`prism test --fingerprint`) lives in
run_linux_tests.sh's --live phase, since it needs deployed relays.
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "prism"
sys.path.insert(0, str(ROOT))  # so `import prism.*` works when run as a script

_passed = 0
_failed = 0


def check(name, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {name}")
    else:
        _failed += 1
        print(f"  [FAIL] {name} -- {detail}")


def _load(path, name, extra_modules=None):
    """Load a .py file as a fresh module under `name`, with any extra_modules
    pre-registered in sys.modules (stubs)."""
    for k, v in (extra_modules or {}).items():
        sys.modules[k] = v
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
def test_rotator_knobs():
    print("rotator knobs (impersonate / upstream_proxy) + session coherence")

    # stub the package + heavy deps rotator_addon imports
    prism = types.ModuleType("prism"); prism.__path__ = []
    subs = {}
    for s in ("cloudflare_relay_manager", "gcp_relay_manager", "azure_relay_manager", "relay_common"):
        m = types.ModuleType("prism." + s); subs["prism." + s] = m; setattr(prism, s, m)
    subs["prism"] = prism
    subs["prism.relay_common"].current_provider = lambda cfg: cfg.get("provider", "gcp")
    hx = types.ModuleType("httpx")
    captured = {}
    hx.AsyncClient = lambda **kw: captured.update(kw) or types.SimpleNamespace(**kw)
    hx.Headers = dict
    hx.URL = lambda u: types.SimpleNamespace(host="relay.example")
    subs["httpx"] = hx
    mm = types.ModuleType("mitmproxy"); mh = types.ModuleType("mitmproxy.http")
    mh.HTTPFlow = object; mh.Response = object; mm.http = mh
    subs["mitmproxy"] = mm; subs["mitmproxy.http"] = mh

    work = tempfile.mkdtemp()
    (Path(work) / "prism.json").write_text(json.dumps({
        "provider": "gcp", "auth_token": "T", "relay_prefix": "p",
        "impersonate": True, "upstream_proxy": "socks5://127.0.0.1:9050",
    }))
    (Path(work) / "endpoints.json").write_text(json.dumps([
        {"url": "https://r1", "name": "p-a", "provider": "gcp"},
        {"url": "https://r2", "name": "p-b", "provider": "gcp"},
    ]))
    old = os.getcwd()
    os.chdir(work)
    try:
        m = _load(PKG / "rotator_addon.py", "rot_under_test", subs)
        R = m.addons[0]
        check("impersonate knob parsed True", R.impersonate is True)
        check("impersonate_profiles populated", R.impersonate_profiles == list(m.IMPERSONATE_PROFILES))
        check("upstream_proxy knob parsed", R.upstream_proxy == "socks5://127.0.0.1:9050")
        check("upstream_proxy passed to httpx client", captured.get("proxy") == "socks5://127.0.0.1:9050",
              f"got {captured.get('proxy')!r}")

        # _fresh_pick returns a profile when impersonating (the coherence guarantee)
        _, ua, prof = R._fresh_pick()
        check("_fresh_pick yields a profile when impersonating", prof in m.IMPERSONATE_PROFILES, f"prof={prof!r}")
        check("_fresh_pick suppresses random UA when impersonating (relay owns it)", ua is None, f"ua={ua!r}")

        # stickiness: same (client,host) keeps the same relay+profile 4-tuple
        class Flow:
            class client_conn: peername = ("10.0.0.1", 1)
        a = R.pick_relay_and_ua(Flow, "login.microsoftonline.com")
        b = R.pick_relay_and_ua(Flow, "login.microsoftonline.com")
        check("session sticks (relay+ua+profile)", a == b and len(a) == 3, f"a={a} b={b}")

        # impersonation OFF -> no profile, UA rotates
        R.impersonate = False; R.impersonate_profiles = []
        _, ua2, prof2 = R._fresh_pick()
        check("impersonate off -> profile None", prof2 is None)
    finally:
        os.chdir(old)


# --------------------------------------------------------------------------
class _FakeImpersonateError(Exception):
    pass


def _fake_curl_cffi(known):
    """A stub curl_cffi whose request() records the call and raises the
    ImpersonateError for any profile not in `known`."""
    calls = []
    cffi = types.ModuleType("curl_cffi")
    req = types.ModuleType("curl_cffi.requests")
    exc = types.ModuleType("curl_cffi.requests.exceptions")
    exc.ImpersonateError = _FakeImpersonateError

    def request(**kw):
        calls.append(kw)
        if kw.get("impersonate") not in known:
            raise _FakeImpersonateError(kw.get("impersonate"))
        return types.SimpleNamespace(status_code=200, content=b"ok",
                                     headers={"X-From": kw.get("impersonate")})
    req.request = request
    cffi.requests = req
    return cffi, req, exc, calls


def _test_relay_fetch(pyfile, modname, extra):
    print(f"relay _fetch ({modname})")
    cffi, req, exc, calls = _fake_curl_cffi(known={"chrome120", "safari17_0"})
    stubs = dict(extra)
    stubs["curl_cffi"] = cffi
    stubs["curl_cffi.requests"] = req
    stubs["curl_cffi.requests.exceptions"] = exc
    m = _load(pyfile, modname, stubs)

    # redirect the plain-requests path to a recorder (no network)
    plain = []
    m.requests = types.SimpleNamespace(request=lambda **kw: plain.append(kw) or
                                       types.SimpleNamespace(status_code=200, content=b"ok", headers={}))

    headers = {"User-Agent": "curl/8", "Accept": "*/*", "Cookie": "s=1", "X-Keep": "yes"}

    # 1) known profile -> curl_cffi used, identity headers stripped, cookies kept
    calls.clear(); plain.clear()
    m._fetch("GET", "https://t/", headers, None, "chrome120")
    used = calls and calls[-1]["impersonate"] == "chrome120"
    sent = calls[-1]["headers"] if calls else {}
    check("known profile uses curl_cffi", bool(used))
    check("identity headers stripped (User-Agent)", "User-Agent" not in sent and "user-agent" not in sent)
    check("identity headers stripped (Accept)", "Accept" not in sent)
    check("non-identity headers kept (Cookie/X-Keep)", sent.get("Cookie") == "s=1" and sent.get("X-Keep") == "yes")
    check("plain requests NOT used on impersonation path", not plain)

    # 2) unknown profile -> falls back to _DEFAULT_IMPERSONATE, no crash
    calls.clear()
    r = m._fetch("GET", "https://t/", headers, None, "chrome999")
    tried = [c["impersonate"] for c in calls]
    check("unknown profile retried with default", tried == ["chrome999", m._DEFAULT_IMPERSONATE], f"tried={tried}")
    check("fallback returns a response (no crash)", getattr(r, "status_code", None) == 200)

    # 3) no profile -> plain requests, curl_cffi untouched
    calls.clear(); plain.clear()
    m._fetch("GET", "https://t/", headers, None, None)
    check("no profile uses plain requests", len(plain) == 1 and not calls)
    check("plain path keeps full headers (UA present)", plain[0]["headers"].get("User-Agent") == "curl/8")


def test_relays():
    ff = types.ModuleType("functions_framework")
    ff.http = lambda f: f
    _test_relay_fetch(PKG / "gcp_relay_function" / "main.py", "gcp_under_test",
                      {"functions_framework": ff})

    az = types.ModuleType("azure"); azf = types.ModuleType("azure.functions")
    azf.AuthLevel = types.SimpleNamespace(ANONYMOUS=1)
    azf.FunctionApp = lambda **kw: types.SimpleNamespace(route=lambda **kw: (lambda f: f))
    azf.HttpRequest = object; azf.HttpResponse = object; az.functions = azf
    _test_relay_fetch(PKG / "azure_relay_function" / "function_app.py", "azure_under_test",
                      {"azure": az, "azure.functions": azf})


# --------------------------------------------------------------------------
def test_worker_strips_impersonate():
    print("worker.js control-header hygiene")
    src = (PKG / "worker.js").read_text().lower()
    check("worker.js strips x-impersonate", "x-impersonate" in src)


def test_config_command():
    """`prism config` toggles knobs by writing prism.json -- so nobody hand-edits
    it. Driven as a subprocess (it's a CLI surface) in a scratch working dir."""
    print("prism config command (knob toggles)")
    work = tempfile.mkdtemp()
    cfgp = Path(work) / "prism.json"
    cfgp.write_text(json.dumps({"provider": "azure", "auth_token": "T", "relay_prefix": "p"}))
    env = dict(os.environ, PYTHONPATH=str(ROOT))

    def run(*a):
        return subprocess.run([sys.executable, "-m", "prism", "--no-banner", "config", *a],
                              cwd=work, env=env, capture_output=True, text=True)

    def cfg():
        return json.loads(cfgp.read_text())

    r = run("impersonate", "on")
    check("config impersonate on -> true", r.returncode == 0 and cfg().get("impersonate") is True, r.stderr[:120])
    r = run("burn", "100")
    check("config burn 100 -> burn_after_requests=100", cfg().get("burn_after_requests") == 100)
    r = run("impersonate", "off")
    check("config impersonate off -> false", cfg().get("impersonate") is False)
    r = run("burn", "off")
    check("config burn off -> 0", cfg().get("burn_after_requests") == 0)
    r = run("impersonate", "maybe")
    check("config rejects bad value (nonzero exit)", r.returncode != 0)
    r = run()
    check("config (no args) prints knobs", r.returncode == 0 and "impersonate" in r.stdout)


def test_trust_command():
    """`prism trust` prints how to make tools trust the rotator CA. Driven with
    HOME/USERPROFILE pointed at an empty dir (no ~/.mitmproxy) so it takes the
    'CA not generated yet' guidance path -- no cert side effects, portable."""
    print("prism trust command")
    work = tempfile.mkdtemp()
    env = dict(os.environ, PYTHONPATH=str(ROOT), HOME=work, USERPROFILE=work)
    r = subprocess.run([sys.executable, "-m", "prism", "--no-banner", "trust"],
                       cwd=work, env=env, capture_output=True, text=True)
    check("trust runs, exits 0 when no CA yet", r.returncode == 0, r.stderr[:120])
    check("trust points at `prism up` to generate the CA", "prism up" in r.stdout)
    check("trust writes no bundle when CA absent",
          not (Path(work) / ".mitmproxy" / "prism-ca-bundle.pem").exists())


def test_wizard_opsec_prompts():
    """The interactive `init` wizard offers impersonate + IP-burning (with an
    explanation of each). Drive _prompt_opsec_knobs with scripted answers.
    Runs FIRST, before other tests stub out the `prism` package in sys.modules."""
    print("init wizard opsec prompts")
    import contextlib
    import prism.cli as cli

    def drive(provider, existing, answers):
        it = iter(answers)
        orig = cli._prompt
        cli._prompt = lambda label, secret=False: next(it, None)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return cli._prompt_opsec_knobs(provider, existing)
        finally:
            cli._prompt = orig

    check("gcp yes/yes -> impersonate on + burn 100",
          drive("gcp", {}, ["y", "y", "100"]) == {"impersonate": True, "burn_after_requests": 100})
    check("gcp no/no -> both off",
          drive("gcp", {}, ["n", "n"]) == {"impersonate": False, "burn_after_requests": 0})
    check("azure Enter keeps existing impersonate on",
          drive("azure", {"impersonate": True}, ["", "n"]).get("impersonate") is True)
    check("cloudflare skips the impersonate prompt (not available)",
          "impersonate" not in drive("cloudflare", {}, ["n"]))
    check("bad burn count falls back to default 100",
          drive("gcp", {}, ["n", "y", "abc"]).get("burn_after_requests") == 100)


def test_cli_error_hints():
    """A failed deploy on a disabled Azure subscription / unbilled GCP project
    should append concrete 'what to do / where to look' guidance rather than
    just echoing the provider's raw error -- and should stay quiet on errors it
    has no specific advice for."""
    print("cli error actionable hints")
    from prism.relay_common import summarize_cli_error

    az = summarize_cli_error(
        "ERROR: (ReadOnlyDisabledSubscription) The subscription "
        "'00000000-0000-0000-0000-000000000000' is disabled and marked read only.")
    check("azure disabled-subscription hint fires", "subscription is disabled or read-only" in az)
    check("azure hint points at the portal", "portal.azure.com" in az)
    check("azure hint echoes the real subscription id",
          "00000000-0000-0000-0000-000000000000" in az.split("Check its state")[-1])
    check("azure hint offers the provider-switch fallback", 'set "provider"' in az)

    gcp = summarize_cli_error("ERROR: Billing account for project 123 is disabled.")
    check("gcp billing-disabled hint fires", "console.cloud.google.com/billing" in gcp)

    plain = summarize_cli_error("ERROR: some transient network timeout")
    check("unrelated error gets NO hint appended", "->" not in plain)

    check("empty stderr still safe", summarize_cli_error("") == "(no error output)")


def test_mitmdump_preflight():
    """`up` preflights the rotator engine before deploying: _verify_mitmdump
    distinguishes a working mitmdump from a crashing one, and _mitmdump_health_hint
    turns the crash into a concrete fix. Uses tiny stand-in 'mitmdump' processes
    so there's no dependency on a real mitmproxy install."""
    print("mitmdump preflight + health hint")
    import prism.cli as cli

    # A non-existent mitmdump must fail cleanly (OSError path), never raise --
    # exercises the real _verify_mitmdump without depending on a mitmproxy
    # install or a platform-specific fake executable.
    ok_missing, out_missing = cli._verify_mitmdump(
        os.path.join(tempfile.gettempdir(), "no-such-mitmdump-xyz"))
    check("preflight fails cleanly on a missing mitmdump", ok_missing is False)
    check("preflight returns a reason, never raises", bool(out_missing))

    hint = cli._mitmdump_health_hint(
        "ModuleNotFoundError: No module named 'zstandard.backend_c'")
    check("zstandard crash -> zstandard-specific fix", "zstandard" in hint and "pipx" in hint)
    check("generic crash -> still gives a fix", "won't start" in cli._mitmdump_health_hint("weird"))


if __name__ == "__main__":
    test_wizard_opsec_prompts()
    test_cli_error_hints()   # before the tests that stub `prism` in sys.modules
    test_mitmdump_preflight()
    test_rotator_knobs()
    test_relays()
    test_worker_strips_impersonate()
    test_config_command()
    test_trust_command()
    print(f"\n{_passed} passed, {_failed} failed")
    sys.exit(1 if _failed else 0)
