/**
 * Cloudflare Worker HTTP relay ("cf-relay")
 * -----------------------------------------
 * Replaces the AWS EC2 + SSH SOCKS node from the original write-up.
 *
 * Deploy the SAME script under many different Worker names (and, for more
 * egress diversity, across more than one Cloudflare account). Each deployed
 * copy gets its own https://<name>.<subdomain>.workers.dev URL. The local
 * rotator (rotator_addon.py) picks one of those URLs per request.
 *
 * How a request flows:
 *   local tool -> mitmproxy (rotator_addon.py) -> THIS WORKER -> real target
 *   response   <- mitmproxy                    <- THIS WORKER <- real target
 *
 * The target only ever sees a Cloudflare edge IP, never your real IP and
 * never the IP of the machine running the rotator.
 *
 * SECURITY: this Worker is an open relay to anyone who knows RELAY_AUTH_TOKEN.
 * Treat that token like a password: generate a long random one per engagement,
 * set it as a Worker secret (do not commit it), and tear the Workers down
 * (see cloudflare_relay_manager.py cleanup) when the engagement ends.
 */

// Prefer a Worker secret over a hardcoded value:
//   wrangler secret put RELAY_AUTH_TOKEN
// Access it below as `env.RELAY_AUTH_TOKEN`. A hardcoded fallback is kept
// here only so the script also works if deployed via the raw API script
// upload path used by cloudflare_relay_manager.py, which does not set secrets.
const FALLBACK_AUTH_TOKEN = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET";

// Headers we never forward in either direction.
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
  "content-encoding",
  "host",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "x-forwarded-for",
  "x-forwarded-proto",
]);

function getTargetUrl(request, url) {
  const headerTarget = request.headers.get("X-Target-URL");
  if (headerTarget) return headerTarget;
  const qpTarget = url.searchParams.get("url");
  if (qpTarget) return qpTarget;
  return null;
}

function buildOutboundHeaders(request) {
  const out = new Headers();
  for (const [key, value] of request.headers) {
    const k = key.toLowerCase();
    // x-impersonate is a control header the rotator may add for GCP/Azure
    // relays; Cloudflare Workers can't control fetch()'s TLS, so we can't act
    // on it -- just make sure it never leaks through to the target.
    if (k === "x-target-url" || k === "x-relay-auth" || k === "x-impersonate" || HOP_BY_HOP.has(k)) {
      continue;
    }
    out.set(key, value);
  }
  return out;
}

export default {
  async fetch(request, env) {
    const authToken = (env && env.RELAY_AUTH_TOKEN) || FALLBACK_AUTH_TOKEN;

    // Constant-ish comparison isn't critical here (this isn't protecting
    // secrets at rest), but do bail out fast on any mismatch.
    if (request.headers.get("X-Relay-Auth") !== authToken) {
      // Return a generic 404 rather than 401/403 so the relay doesn't
      // announce itself to internet-wide scanners.
      return new Response("Not found", { status: 404 });
    }

    const url = new URL(request.url);
    const target = getTargetUrl(request, url);
    if (!target) {
      return new Response(
        "Missing target. Set the X-Target-URL header or ?url= query param.",
        { status: 400 }
      );
    }

    let targetUrl;
    try {
      targetUrl = new URL(target);
    } catch (e) {
      return new Response("Invalid target URL", { status: 400 });
    }
    if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
      return new Response("Unsupported target scheme: " + targetUrl.protocol, {
        status: 400,
      });
    }

    const init = {
      method: request.method,
      headers: buildOutboundHeaders(request),
      redirect: "manual", // let the caller decide how to handle 3xx
    };
    if (!["GET", "HEAD"].includes(request.method)) {
      init.body = request.body;
    }

    let response;
    try {
      response = await fetch(targetUrl.toString(), init);
    } catch (e) {
      return new Response("Upstream fetch failed: " + e.message, {
        status: 502,
      });
    }

    const respHeaders = new Headers();
    for (const [key, value] of response.headers) {
      if (HOP_BY_HOP.has(key.toLowerCase())) continue;
      respHeaders.set(key, value);
    }
    respHeaders.set("Access-Control-Allow-Origin", "*");
    respHeaders.set("X-Relay-Origin", targetUrl.hostname);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
    });
  },
};
