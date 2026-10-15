"""
gcp_relay_function/main.py
---------------------------
GCP Cloud Functions (2nd gen) equivalent of worker.js -- same relay, same
wire protocol (X-Relay-Auth / X-Target-URL headers), so rotator_addon.py
and endpoints.json work identically regardless of which provider deployed
the relay. Deployed by gcp_relay_manager.py via `gcloud functions deploy`.

SECURITY: like worker.js, this is an open relay to anyone holding
RELAY_AUTH_TOKEN. Treat that token like a password and tear the functions
down (prism down) when the engagement ends.
"""

import os

import functions_framework
import requests

try:
    # curl_cffi reproduces a real browser's TLS ClientHello + HTTP/2 handshake,
    # so an impersonated request presents a matching JA3 / JA4 / JA4+ to the
    # target instead of this runtime's default fingerprint. Optional: absent on
    # older deploys, in which case impersonation silently falls back below.
    from curl_cffi import requests as cffi_requests
except Exception:
    cffi_requests = None
try:
    # Raised (before any network I/O) when this curl_cffi doesn't know a
    # requested profile -- the only case we retry with a default. Network
    # errors are other RequestException subclasses and must NOT be swallowed.
    from curl_cffi.requests.exceptions import ImpersonateError as _ImpersonateError
except Exception:
    _ImpersonateError = ValueError

# Fallback profile if the rotator asks for one this deploy's curl_cffi doesn't
# recognize (e.g. rotator newer than the relay's pinned curl_cffi).
_DEFAULT_IMPERSONATE = "chrome120"

# gcp_relay_manager.py sets this as a real env var at deploy time
# (--set-env-vars). The fallback only matters if this is ever invoked
# without that -- keep it obviously invalid so a misconfigured deploy
# fails closed rather than open.
AUTH_TOKEN = os.environ.get("RELAY_AUTH_TOKEN", "CHANGE_ME_TO_A_LONG_RANDOM_SECRET")

# Headers we never forward in either direction -- mirrors worker.js.
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
    "x-cloud-trace-context",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-appengine-country",
}

# When impersonating, curl_cffi sets a coherent browser identity (User-Agent,
# client hints, Accept*, ...) that must match the TLS/HTTP2 handshake. Drop the
# client's own versions so they don't override it and break JA4H header
# coherence; everything else (cookies, auth, content-type, referer, ...) still
# passes through.
IMPERSONATE_STRIP = {
    "user-agent", "accept", "accept-encoding", "accept-language",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-arch",
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-model",
    "sec-ch-ua-platform-version", "sec-ch-ua-bitness",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests", "priority",
}


def _fetch(method, url, headers, body, profile):
    """Outbound request to the real target. With an impersonation profile and
    curl_cffi available, reproduce a real browser's TLS + HTTP/2 handshake so
    the target sees a matching JA3/JA4/JA4+; otherwise a plain requests call.
    A profile curl_cffi doesn't recognize falls back to a default, then to a
    plain request; network errors propagate to the caller."""
    if profile and cffi_requests is not None:
        cffi_headers = {k: v for k, v in headers.items() if k.lower() not in IMPERSONATE_STRIP}
        for target_profile in (profile, _DEFAULT_IMPERSONATE):
            try:
                return cffi_requests.request(
                    method=method, url=url, headers=cffi_headers, data=body,
                    impersonate=target_profile, allow_redirects=False, timeout=25,
                )
            except _ImpersonateError:
                continue  # unrecognized profile -> try the default, then plain requests
    return requests.request(
        method=method, url=url, headers=headers, data=body,
        allow_redirects=False, timeout=25,
    )


def _target_url(request):
    header_target = request.headers.get("X-Target-URL")
    if header_target:
        return header_target
    return request.args.get("url")


def _outbound_headers(request):
    out = {}
    for key, value in request.headers.items():
        k = key.lower()
        if k in ("x-target-url", "x-relay-auth", "x-impersonate") or k in HOP_BY_HOP:
            continue
        out[key] = value
    return out


@functions_framework.http
def relay(request):
    # Return a generic 404 rather than 401/403 so the relay doesn't
    # announce itself to internet-wide scanners -- mirrors worker.js.
    if request.headers.get("X-Relay-Auth") != AUTH_TOKEN:
        return ("Not found", 404)

    target = _target_url(request)
    if not target:
        return ("Missing target. Set the X-Target-URL header or ?url= query param.", 400)

    if not (target.startswith("http://") or target.startswith("https://")):
        return ("Unsupported target scheme", 400)

    body = request.get_data() if request.method not in ("GET", "HEAD") else None
    profile = request.headers.get("X-Impersonate")
    try:
        resp = _fetch(request.method, target, _outbound_headers(request), body, profile)
    except Exception as e:
        return (f"Upstream fetch failed: {e}", 502)

    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"
    }
    resp_headers["Access-Control-Allow-Origin"] = "*"
    resp_headers["X-Relay-Origin"] = requests.utils.urlparse(target).hostname or ""

    return (resp.content, resp.status_code, resp_headers)
