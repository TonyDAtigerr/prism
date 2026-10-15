"""
rotator_addon.py
-----------------
Local half of the tool -- replaces proxy-ng from the original write-up.

proxy-ng randomly picked among several *local* SOCKS ports, each an SSH
tunnel into a specific EC2 VM. There is no SOCKS/TCP equivalent for any of
the three providers this tool supports (they only speak HTTP), so this is
an mitmproxy addon instead: mitmproxy terminates the client's TLS locally
(as Burp/ZAP do), and for every request this addon picks a deployed relay
endpoint from endpoints.json and replays the request through it, along
with a User-Agent from useragents.json. Provider-agnostic -- it works the
same whether endpoints.json holds Cloudflare Worker URLs, GCP Cloud
Function URLs, or Azure Function URLs, since all three relays
(worker.js / gcp_relay_function / azure_relay_function) implement the
exact same X-Relay-Auth / X-Target-URL wire protocol.

All of the knobs below are optional fields in prism.json. None
of them change behavior unless you set them -- defaults match the original
"fresh random pick every request, no delay, never redeploy" behavior except
for sticky_seconds, which defaults on (see why below).

Sticky sessions ("sticky_seconds", default 300): the SAME (client, target
host) pair keeps using the same relay + User-Agent for this many seconds
before a fresh one is picked. This matters for anything that's a
multi-step flow rather than one-shot requests -- e.g. an OAuth/login
sequence with redirects and cookies -- since the source IP (and UA)
jumping mid-flow is itself an anomaly signal independent of IP reputation.
Set to 0 to go back to a fresh pick every single request (fine for
independent one-shot probes like a scanner hitting a target list).

Pacing ("pacing_min_seconds"/"pacing_max_seconds", default 0/0 = off): adds
a random delay in that range before every request is forwarded, regardless
of whatever pacing the calling tool does (or doesn't) implement on its own.
Useful for tools with no built-in rate limiting of their own.

Burn policy ("burn_after_requests"/"burn_after_seconds", default 0/0 =
off): once a relay has handled this many requests, or has been in the pool
this long, it's retired -- a fresh replacement relay is deployed via
whichever provider is active, the old one is deleted, and endpoints.json
is rewritten -- so no single relay accumulates target-side reputation for
the rest of a long engagement. Requires the same credentials already in
prism.json; deploy/delete calls block briefly when a burn fires
(rare, compared to per-request traffic), reusing that provider's own
backend module (cloudflare_relay_manager.py / gcp_relay_manager.py /
azure_relay_manager.py).

TLS/HTTP2 impersonation ("impersonate", default false; GCP/Azure only): when
true, each request is tagged with a browser profile (Chrome/Edge/Safari) and
the relay reproduces that browser's exact TLS ClientHello and HTTP/2 handshake
with curl_cffi, so the target sees a real-browser JA3 / JA4 / JA4+ fingerprint
instead of the function runtime's default. The chosen browser is coherent per
sticky session (the relay owns the User-Agent + client-hint headers to match
the handshake, so a "Chrome" UA never rides a non-Chrome fingerprint).
Cloudflare Workers can't control fetch()'s TLS, so this is a no-op there --
the relay simply ignores the header. Requires the relay function to have been
(re)deployed with curl_cffi in its requirements (rerun `prism up --redeploy`
after enabling on an older deploy).

Upstream proxy ("upstream_proxy", default none): routes the rotator -> relay
leg through a proxy you control (a burner VPS/VPN/Tor), e.g.
"socks5://127.0.0.1:9050" or "http://vps:8080". Its headline job is the
Cloudflare real-IP leak: Cloudflare appends whatever IP connects to it onto
X-Forwarded-For (after the Worker runs, so it can't be stripped), and that IP
is the box running this rotator -- i.e. yours. Sending the leg through a burner
first makes the leaked IP disposable rather than your real one. Applies to
every provider as a general extra hop; each relay's own TLS cert is still
verified end-to-end through the proxy, so the hop can't MITM the relay leg.
SOCKS URLs need httpx's socks extra (shipped: httpx[socks]).

Setup:
    pip install -r requirements.txt

Run:
    mitmdump -s rotator_addon.py -p 9292

Then point your browser / Burp / scanner's proxy settings at
127.0.0.1:9292 (SOCKS proxy config in the original write-up becomes plain
HTTP/HTTPS proxy config here -- see the "Example Usage" section of the
updated write-up). The first time a client talks HTTPS through mitmproxy
it will need to trust mitmproxy's local CA -- see
https://docs.mitmproxy.org/stable/concepts-certificates/
"""

import asyncio
import json
import random
import time
from pathlib import Path

import httpx
from mitmproxy import http

import prism.cloudflare_relay_manager as cfm
import prism.gcp_relay_manager as gcpm
import prism.azure_relay_manager as azm
import prism.relay_common as rc

BACKENDS = {"cloudflare": cfm, "gcp": gcpm, "azure": azm}

ENDPOINTS_PATH = Path("endpoints.json")
# Runtime state (ENDPOINTS_PATH, CONFIG_PATH) stays relative to the working
# directory the user runs `prism up` from. useragents.json is a bundled data
# file, so it must resolve next to this module -- otherwise a pipx/pip install
# (where the package lives outside the user's cwd) can't find it.
USERAGENTS_PATH = Path(__file__).resolve().parent / "useragents.json"
CONFIG_PATH = Path("prism.json")
DEFAULT_STICKY_SECONDS = 300

# TLS/HTTP2 impersonation profiles (GCP/Azure only -- see the "impersonate"
# knob in the module docstring). When enabled, the rotator tags each request
# with one of these via the X-Impersonate header; the relay reproduces that
# browser's exact ClientHello + HTTP/2 handshake with curl_cffi, so the target
# sees a matching JA3 / JA4 / JA4+ instead of the function runtime's default
# fingerprint. Names are curl_cffi impersonation targets; the relay falls back
# safely if its installed curl_cffi doesn't recognize one. Cloudflare Workers
# can't do this (fetch() exposes no TLS control), so it ignores the header.
IMPERSONATE_PROFILES = [
    "chrome120", "chrome123", "chrome124", "chrome131",
    "edge101", "edge99",
    "safari15_5", "safari17_0",
]

# Headers stripped before handing the request to httpx, mirroring worker.js.
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
    "host",
}


class Rotator:
    def __init__(self):
        if not CONFIG_PATH.exists():
            raise SystemExit(f"Missing {CONFIG_PATH} -- run `prism init` first.")
        self.cfg = json.loads(CONFIG_PATH.read_text())
        self.backend = BACKENDS[rc.current_provider(self.cfg)]
        self.auth_token = self.cfg["auth_token"]
        self.sticky_seconds = self.cfg.get("sticky_seconds", DEFAULT_STICKY_SECONDS)
        self.pacing_min = max(0.0, self.cfg.get("pacing_min_seconds", 0))
        self.pacing_max = max(self.pacing_min, self.cfg.get("pacing_max_seconds", 0))
        self.burn_after_requests = self.cfg.get("burn_after_requests", 0)
        self.burn_after_seconds = self.cfg.get("burn_after_seconds", 0)
        # TLS/HTTP2 impersonation (GCP/Azure relays only). When on, each request
        # is tagged with a browser profile the relay reproduces via curl_cffi.
        self.impersonate = bool(self.cfg.get("impersonate", False))
        self.impersonate_profiles = list(IMPERSONATE_PROFILES) if self.impersonate else []
        # Optional upstream proxy for the rotator -> relay leg (a burner
        # VPS/VPN/Tor). Its main job is Cloudflare's XFF real-IP leak: Cloudflare
        # appends whatever IP connects to it, so routing through a burner makes
        # the leaked IP disposable instead of yours. Applies to every provider
        # (defense in depth). e.g. "socks5://127.0.0.1:9050" or "http://vps:8080".
        self.upstream_proxy = self.cfg.get("upstream_proxy") or None

        if not ENDPOINTS_PATH.exists():
            raise SystemExit(f"Missing {ENDPOINTS_PATH} -- run `prism up` first.")
        self.endpoints = json.loads(ENDPOINTS_PATH.read_text())
        if not self.endpoints:
            raise SystemExit(f"{ENDPOINTS_PATH} is empty -- run `prism up` first.")

        self.user_agents = []
        if USERAGENTS_PATH.exists():
            self.user_agents = json.loads(USERAGENTS_PATH.read_text()).get("UserAgents", [])

        # Async client (not httpx.Client) -- this hook runs as a coroutine so
        # pacing's asyncio.sleep() doesn't stall every other concurrent flow
        # along with it; a blocking sync call here would defeat that. verify=True
        # still checks each relay's own cert end-to-end even through a proxy
        # (httpx CONNECT-tunnels), so the upstream hop can't MITM the relay leg.
        self.client = httpx.AsyncClient(timeout=30.0, verify=True, proxy=self.upstream_proxy)

        # (client_ip, target_host) -> (relay_url, user_agent, profile, expires_at).
        # Keyed on target host (not full URL) so an entire multi-request flow
        # against one site -- redirects, XHRs, the works -- sticks together, and
        # holds one browser identity (relay + UA + impersonation profile) for it.
        self._sticky = {}

        now = time.time()
        self._usage_count = {ep["url"]: 0 for ep in self.endpoints}
        self._first_seen = {ep["url"]: now for ep in self.endpoints}
        self._burn_lock = asyncio.Lock()

        if self.burn_after_requests or self.burn_after_seconds:
            print(
                f"[rotator] burn policy active: "
                f"after_requests={self.burn_after_requests or '-'} "
                f"after_seconds={self.burn_after_seconds or '-'}"
            )
        if self.pacing_max > 0:
            print(f"[rotator] pacing active: {self.pacing_min}-{self.pacing_max}s per request")
        if self.impersonate:
            print("[rotator] TLS/HTTP2 impersonation active (GCP/Azure relays): "
                  "target sees a real-browser JA3/JA4 fingerprint per session")
        if self.upstream_proxy:
            print(f"[rotator] upstream proxy active: rotator -> relay leg routed via "
                  f"{self.upstream_proxy} (Cloudflare's XFF leak now exposes that IP, not yours)")

    def _fresh_pick(self):
        relay_url = random.choice(self.endpoints)["url"]
        # When impersonating, the relay owns the browser identity (UA + client
        # hints must match the TLS handshake), so we send a profile and let the
        # relay set a coherent UA rather than picking an unrelated one here.
        if self.impersonate_profiles:
            return relay_url, None, random.choice(self.impersonate_profiles)
        user_agent = random.choice(self.user_agents) if self.user_agents else None
        return relay_url, user_agent, None

    def _prune_sticky(self, now):
        expired = [k for k, (_, _, _, expires_at) in self._sticky.items() if expires_at <= now]
        for k in expired:
            del self._sticky[k]

    def pick_relay_and_ua(self, flow, target_host):
        if self.sticky_seconds <= 0:
            return self._fresh_pick()

        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        key = (client_ip, target_host)
        now = time.time()

        cached = self._sticky.get(key)
        if cached and cached[3] > now:
            return cached[0], cached[1], cached[2]

        relay_url, user_agent, profile = self._fresh_pick()
        self._prune_sticky(now)
        self._sticky[key] = (relay_url, user_agent, profile, now + self.sticky_seconds)
        return relay_url, user_agent, profile

    async def request(self, flow: http.HTTPFlow) -> None:
        target_url = flow.request.pretty_url
        relay_url, user_agent, impersonate = self.pick_relay_and_ua(flow, flow.request.host)

        if self.pacing_max > 0:
            await asyncio.sleep(random.uniform(self.pacing_min, self.pacing_max))

        # httpx.Headers is case-insensitive, so the User-Agent override below
        # replaces the client's forwarded UA instead of leaving a duplicate
        # lowercase "user-agent" beside it -- HTTP/2 client requests hand us
        # lowercased header names, so a plain dict would carry both.
        out_headers = httpx.Headers(
            {k: v for k, v in flow.request.headers.items() if k.lower() not in HOP_BY_HOP}
        )
        if user_agent:
            out_headers["User-Agent"] = user_agent

        out_headers["X-Relay-Auth"] = self.auth_token
        out_headers["X-Target-URL"] = target_url
        # Ask the relay to reproduce this session's browser TLS/HTTP2 handshake
        # (GCP/Azure honor it; Cloudflare can't and ignores it). The relay owns
        # the matching UA + client-hint headers, so we don't set a UA above when
        # a profile is in play -- keeping the fingerprint and headers coherent.
        if impersonate:
            out_headers["X-Impersonate"] = impersonate
        # Pin this hop's Host to the RELAY's own hostname. The relay sits behind
        # Cloudflare (GCP/Azure dispatch on Host too); if the client's *target*
        # host reaches the edge here, Cloudflare answers 1003 "Direct IP access
        # not allowed" before our relay code ever runs. Client requests over
        # HTTP/2 carry no Host header at all (the authority is a pseudo-header,
        # absent from .headers), so set it explicitly rather than trusting httpx
        # to infer it from the URL.
        out_headers["Host"] = httpx.URL(relay_url).host

        try:
            resp = await self.client.request(
                method=flow.request.method,
                url=relay_url,
                headers=out_headers,
                content=flow.request.raw_content,
            )
        except httpx.HTTPError as e:
            flow.response = http.Response.make(
                502, f"cf-relay error via {relay_url}: {e}".encode(), {"Content-Type": "text/plain"}
            )
            return

        resp_headers = {
            k: v
            for k, v in resp.headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"
        }
        flow.response = http.Response.make(resp.status_code, resp.content, resp_headers)

        await self._record_use_and_maybe_burn(relay_url)

    async def _record_use_and_maybe_burn(self, relay_url):
        if not (self.burn_after_requests or self.burn_after_seconds):
            return

        self._usage_count[relay_url] = self._usage_count.get(relay_url, 0) + 1
        count = self._usage_count[relay_url]
        age = time.time() - self._first_seen.get(relay_url, time.time())

        over_requests = self.burn_after_requests and count >= self.burn_after_requests
        over_age = self.burn_after_seconds and age >= self.burn_after_seconds
        if not (over_requests or over_age):
            return

        async with self._burn_lock:
            # Re-check under the lock -- another concurrent request may have
            # already burned this exact relay while we were waiting on it.
            if relay_url not in self._usage_count:
                return
            reason = "request count" if over_requests else "age"
            print(f"[rotator] burning {relay_url} (exceeded {reason} threshold)")
            await asyncio.to_thread(self._burn_and_replace, relay_url)

    def _burn_and_replace(self, old_url):
        """Synchronous -- deploys one fresh relay, deletes the old one, and
        rewrites endpoints.json. Runs off the event loop via to_thread since
        it's a handful of blocking API/CLI calls, but this only fires once
        per burn_after_* threshold crossed, not on every request. Uses
        self.backend (whichever provider is active) via the uniform
        deploy_one_relay(cfg, name) / delete_one(cfg, name) interface every
        backend module exposes -- burn works the same regardless of provider."""
        old_entry = next((e for e in self.endpoints if e["url"] == old_url), None)
        if old_entry is None:
            return  # already burned by a racing request, or not ours

        provider = rc.current_provider(self.cfg)
        new_name = f"{rc.name_prefix(self.cfg)}-{rc.random_suffix()}"
        try:
            new_url = self.backend.deploy_one_relay(self.cfg, new_name)
        except Exception as e:
            print(f"[rotator] burn: failed to deploy a replacement for {old_url}: {e} -- keeping it in rotation")
            return
        if not new_url:
            print(f"[rotator] burn: failed to deploy a replacement for {old_url}, keeping it in rotation")
            return
        new_entry = {"name": new_name, "url": new_url, "provider": provider}

        self.endpoints = [e for e in self.endpoints if e["url"] != old_url] + [new_entry]
        ENDPOINTS_PATH.write_text(json.dumps(self.endpoints, indent=2))

        self._usage_count.pop(old_url, None)
        self._first_seen.pop(old_url, None)
        self._usage_count[new_entry["url"]] = 0
        self._first_seen[new_entry["url"]] = time.time()

        # Any sticky sessions pinned to the burned relay need a fresh pick
        # next time -- otherwise they'd keep trying a URL we're deleting.
        for key in [k for k, v in self._sticky.items() if v[0] == old_url]:
            del self._sticky[key]

        if self.backend.delete_one(self.cfg, old_entry["name"]):
            print(f"[rotator] burn: replaced {old_url} -> {new_entry['url']}")
        else:
            print(
                f"[rotator] burn: deployed {new_entry['url']}, but deleting old "
                f"{old_entry['name']} failed -- clean it up manually later"
            )


addons = [Rotator()]
