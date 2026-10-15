# One tool, three egress fabrics, three detection profiles

Prism deploys the *same* HTTP relay to Cloudflare Workers, GCP Cloud Functions, or
Azure Functions, and the local rotator talks to all three identically. But the target
never sees "Prism" — it sees traffic arriving from whichever cloud you deployed to. And
those three clouds present very differently to a detection stack. Picking the provider is,
in practice, picking which detections you trip and which you slip.

This is written for **authorized** red-team work; the same facts tell a blue team exactly
what to watch for, so the defensive mirror is at the end.

## The detection surfaces that matter

A target (or the WAF / IP-intel / SIEM in front of it) can judge inbound traffic on:

1. **ASN / IP classification** — is this IP a residential ISP, a CDN, or a datacenter/
   "hosting" range? IP-intelligence feeds score these very differently.
2. **Published cloud ranges** — GCP and Azure *publish exact CIDR lists*; a defender can
   match against them directly.
3. **Header artifacts** — `X-Forwarded-For`, `Via`, and provider-injected headers can
   reveal the hop chain — or your real IP.
4. **TLS fingerprint (JA3/JA4)** — the *relay* makes the final TLS connection to the
   target, so the fingerprint the target sees belongs to the provider runtime, not your
   client.
5. **Behavioral / rate** — request cadence, per-session source churn, UA/JA3 coherence.

Prism moves the first three around by provider, partially controls #5 (pacing, sticky
sessions, per-request rotation), and does **not** disguise #4.

## Provider by provider

### Cloudflare Workers — trusted ASN, but it leaks your real IP

- **Egress:** Cloudflare's network, **AS13335** — one of the busiest ASNs on the internet,
  carrying vast amounts of legitimate CDN traffic. IP-intel feeds rarely score it as
  "hosting/abuse," so baseline suspicion is low and wholesale-blocking it risks heavy
  collateral damage to real users.
- **The catch — real-IP leak:** Cloudflare appends the connecting client's IP (the machine
  running the rotator — *your* IP) to `X-Forwarded-For` / `CF-Connecting-IP` **after** the
  Worker runs, so the Worker can't strip it. Any target that reads `X-Forwarded-For` —
  which is most apps behind a proxy, WAF, or load balancer — logs your real IP even though
  the TCP connection is Cloudflare's. **Against an XFF-inspecting target, Cloudflare defeats
  the entire purpose.** (Verified against a live deploy.)
- **Best when:** you want low-reputation-suspicion egress **and** you've confirmed the
  target doesn't consume `X-Forwarded-For`.

### GCP Cloud Functions — clean egress, but fully enumerable

- **Egress:** Google Cloud ranges. The target sees only Google's egress IP, in both the
  connection and the headers — **no real-IP leak** (verified).
- **The catch — enumerability:** Google publishes its ranges
  (`https://www.gstatic.com/ipranges/cloud.json`). A defender can block or flag "all of
  GCP" with one ruleset, and IP-intel feeds classify these as datacenter/cloud, so baseline
  suspicion is higher than Cloudflare's.
- **Best when:** you must hide your real IP from a header-inspecting target and the target
  is *not* blanket-blocking cloud ranges.

### Azure Functions — clean egress, published as Service Tags

- **Egress:** Azure datacenter ranges. Like GCP, the target sees only the provider egress
  IP with **no real-IP leak**.
- **The catch — Service Tags:** Azure publishes its ranges as downloadable **Service Tags**,
  so the same enumerate-and-block logic applies, and the "cloud/hosting" reputation penalty
  is similar to GCP's.
- **Best when:** same as GCP — real-IP hiding matters and cloud-range blocking isn't in
  play; useful for varying which cloud's ranges you present.

## At a glance

| | Cloudflare Workers | GCP Cloud Functions | Azure Functions |
|---|---|---|---|
| Egress class | CDN (AS13335) | Datacenter / cloud | Datacenter / cloud |
| Reputation baseline | Low suspicion | Higher | Higher |
| Ranges enumerable? | Hard to block cleanly | Yes (`cloud.json`) | Yes (Service Tags) |
| Leaks your real IP? | **Yes (XFF/CF-Connecting-IP)** | No | No |
| URL suffix | `*.workers.dev` | `*.cloudfunctions.net` / `*.run.app` | `*.azurewebsites.net` |
| Use it when | Target ignores XFF; want CDN rep | Hide real IP; ranges not blocked | Hide real IP; vary cloud presented |

## What Prism does and doesn't disguise

- **Does:** source IP at the TCP layer (all three), per-request relay + User-Agent
  rotation, sticky sessions so a multi-request flow holds one relay, request pacing, and
  burn-after-N relay recycling.
- **TLS fingerprint (JA3/JA4/JA4+) — on GCP and Azure, optionally:** with the
  `impersonate` knob on, those relays reproduce a real browser's TLS ClientHello and
  HTTP/2 handshake (via `curl_cffi`), so the target sees a genuine-browser JA3/JA4 plus a
  coherent User-Agent and client hints — no "Chrome UA over a Python JA3" tell. The browser
  identity is picked per sticky session so it stays consistent across a flow. **Cloudflare
  can't do this** (`fetch()` exposes no TLS control), so there the JA3/JA4 remains the
  Workers runtime's — a third Cloudflare-specific limitation alongside the XFF leak and the
  enumerable-vs-reputation trade-off.
- **Doesn't:** Prism is **HTTP(S)-only** (no raw TCP), and on Cloudflare both the XFF
  real-IP leak and the runtime TLS fingerprint stand regardless.

## The defensive mirror (blue team)

Everything above is a detection you can build:

- **Match published cloud ranges.** Ingest Azure Service Tags, Google `cloud.json`, and
  Cloudflare's ranges; tag or deny inbound traffic from function-egress space that has no
  business reaching your app.
- **Turn the Cloudflare leak into a signal.** The XFF real-IP append is a *gift* — log the
  full `X-Forwarded-For` chain and alert when it ends in Cloudflare egress with a mismatched
  `CF-Connecting-IP`; you may recover the operator's real IP for free.
- **JA3/UA coherence.** Flag a browser User-Agent presenting a datacenter/runtime JA3.
- **Behavioral churn.** Watch for a single logical session whose source IP changes
  per-request, and for unnaturally uniform request spacing.

## Takeaway

The technique (cloud egress rotation) isn't new, but the *provider choice* is a real,
underappreciated knob: Cloudflare buys reputation at the cost of a real-IP leak; GCP and
Azure give clean egress that any defender can enumerate and block. Knowing which trade you're
making — per engagement, per target — is the point. Prism just makes switching between the
three a one-flag decision so you can test all three profiles against the same target.

> **Authorization:** only point this at systems you're explicitly authorized to test. Tear
> relays down when the engagement ends. Provider Terms of Service and Acceptable Use
> Policies apply to this traffic like any other.
