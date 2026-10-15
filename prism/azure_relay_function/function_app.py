"""
azure_relay_function/function_app.py
--------------------------------------
Azure Functions (Python v2 programming model) equivalent of worker.js --
same relay, same wire protocol (X-Relay-Auth / X-Target-URL headers), so
rotator_addon.py and endpoints.json work identically regardless of which
provider deployed the relay. Deployed by azure_relay_manager.py via a zip
push deploy (az functionapp deployment source config-zip).

SECURITY: like worker.js, this is an open relay to anyone holding
RELAY_AUTH_TOKEN. Treat that token like a password and tear the function
apps down (prism down) when the engagement ends.
"""

import os

import azure.functions as func
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

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# azure_relay_manager.py sets this as a real app setting at deploy time.
# The fallback only matters if this is ever invoked without that -- keep
# it obviously invalid so a misconfigured deploy fails closed, not open.
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
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-waws-unencoded-url",
    "x-arr-log-id",
    "disguised-host",
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


def _target_url(req: func.HttpRequest):
    header_target = req.headers.get("X-Target-URL")
    if header_target:
        return header_target
    return req.params.get("url")


def _outbound_headers(req: func.HttpRequest):
    out = {}
    for key, value in req.headers.items():
        k = key.lower()
        if k in ("x-target-url", "x-relay-auth", "x-impersonate") or k in HOP_BY_HOP:
            continue
        out[key] = value
    return out


@app.route(route="relay", methods=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def relay(req: func.HttpRequest) -> func.HttpResponse:
    # Return a generic 404 rather than 401/403 so the relay doesn't
    # announce itself to internet-wide scanners -- mirrors worker.js.
    if req.headers.get("X-Relay-Auth") != AUTH_TOKEN:
        return func.HttpResponse("Not found", status_code=404)

    target = _target_url(req)
    if not target:
        return func.HttpResponse(
            "Missing target. Set the X-Target-URL header or ?url= query param.", status_code=400
        )

    if not (target.startswith("http://") or target.startswith("https://")):
        return func.HttpResponse("Unsupported target scheme", status_code=400)

    body = req.get_body() if req.method not in ("GET", "HEAD") else None
    profile = req.headers.get("X-Impersonate")
    try:
        resp = _fetch(req.method, target, _outbound_headers(req), body, profile)
    except Exception as e:
        return func.HttpResponse(f"Upstream fetch failed: {e}", status_code=502)

    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"
    }
    resp_headers["Access-Control-Allow-Origin"] = "*"
    resp_headers["X-Relay-Origin"] = requests.utils.urlparse(target).hostname or ""

    return func.HttpResponse(resp.content, status_code=resp.status_code, headers=resp_headers)
