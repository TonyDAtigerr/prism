#!/usr/bin/env bash
#
# run_linux_tests.sh -- native Linux test runner for Prism.
# ---------------------------------------------------------
# Re-runs Prism's test suite on Linux/macOS, including the POSIX-specific
# paths that can't be exercised on Windows: `export`/`curl -x`, the SIGINT
# (Ctrl+C) confirm prompt with its SIGSTOP-pause of mitmdump, and a SOCKS5
# listener wrapped with proxychains. Mirrors the "Prism Test Matrix" checklist.
#
# Usage:
#   ./run_linux_tests.sh                 # offline CLI/config tests only (no cloud)
#   ./run_linux_tests.sh --live          # + a full live lifecycle against your
#                                         #   CONFIGURED provider (DEPLOYS billable
#                                         #   relays, then tears them down)
#
# Env overrides:  PORT=9393  PY=python3.11  ./run_linux_tests.sh --live
#
# Safety: your prism.json and endpoints.json are backed up on start and
# restored on exit (even on Ctrl+C / error). The --live phase always tears
# down what it deploys. It will NOT touch your resource group / storage
# account (never runs --purge-infra).
#
set -u

# --------------------------------------------------------------------------
PY="${PY:-python3}"
# A currently-free TCP port straight from the OS. Using a fresh one instead of a
# hardcoded 9292 means a leftover process from an earlier run can't squat the
# port and cascade into false FAILs: `up`'s port guard fires *before* the check
# each test is meant to exercise, so a busy port surfaces as bogus "count
# range"/"rotator won't start" failures rather than what it really is.
free_port(){ "$PY" -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()' 2>/dev/null; }
PORT="${PORT:-$(free_port)}"; PORT="${PORT:-9292}"
LIVE=0
[ "${1:-}" = "--live" ] && LIVE=1
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT" || { echo "cannot cd to script dir"; exit 1; }

PASS=0; FAIL=0; SKIP=0
ok(){ printf '  \033[32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no(){ printf '  \033[31m[FAIL]\033[0m %s -- %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }
sk(){ printf '  \033[33m[SKIP]\033[0m %s -- %s\n' "$1" "${2:-}"; SKIP=$((SKIP+1)); }
sec(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# poll a file for a string, up to $3 tenths of a second (default 120 = 12s)
wait_for(){ local pat="$1" f="$2" n="${3:-120}" i=0; while [ "$i" -lt "$n" ]; do grep -q "$pat" "$f" 2>/dev/null && return 0; sleep 0.1; i=$((i+1)); done; return 1; }

# poll until TCP port $1 actually accepts a connection (up to $2 tenths of a
# second, default 100 = 10s). `up` prints "Starting rotator" *before* it spawns
# mitmdump, which then takes a moment to bind -- curling on the banner alone
# races the bind and gets a connection-refused (empty result).
wait_port(){ local p="$1" n="${2:-100}" i=0; while [ "$i" -lt "$n" ]; do "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(('127.0.0.1',int('$p')))==0 else 1)" 2>/dev/null && return 0; sleep 0.1; i=$((i+1)); done; return 1; }

# best-effort: kill whatever is LISTENing on TCP port $1. Belt-and-suspenders so
# the test port is always free again on exit even if a rotator got orphaned.
kill_port(){
  local p="$1" pids=""
  if   have lsof; then pids="$(lsof -tiTCP:"$p" -sTCP:LISTEN 2>/dev/null)"
  elif have ss;   then pids="$(ss -H -ltnp "sport = :$p" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)"
  fi
  [ -n "$pids" ] && kill $pids 2>/dev/null
}

# --------------------------------------------------------------------------
# safety: back up live config/endpoints, restore + clean up on any exit
# explicit template: GNU mktemp accepts a bare `mktemp -d`, but BSD/macOS
# mktemp requires a template or -t, so the bare form aborts the whole run on a Mac.
BAK="$(mktemp -d "${TMPDIR:-/tmp}/prism.XXXXXX")"
[ -f prism.json ]     && cp prism.json     "$BAK/prism.json"
[ -f endpoints.json ] && cp endpoints.json "$BAK/endpoints.json"
cleanup(){
  # Tear down the rotator completely: the `up` wrapper (UPPID), its mitmdump
  # child -- which start_new_session detaches into its own session, so killing
  # UPPID alone leaves it running -- and anything still holding the test port.
  # Without this an orphaned mitmdump survives to squat the port on the next run.
  [ -n "${MITMPID:-}" ] && kill "$MITMPID" 2>/dev/null
  [ -n "${UPPID:-}" ]   && kill "$UPPID"   2>/dev/null
  pkill -f "mitmdump -s rotator_addon.py" 2>/dev/null
  kill_port "$PORT" 2>/dev/null
  rm -f prism.json endpoints.json
  [ -f "$BAK/prism.json" ]     && cp "$BAK/prism.json"     prism.json
  [ -f "$BAK/endpoints.json" ] && cp "$BAK/endpoints.json" endpoints.json
  rm -rf "$BAK" .prism_up.out .prism_ctl 2>/dev/null
}
trap cleanup EXIT INT TERM

CFG_CF='{"provider":"cloudflare","api_token":"t","account_id":"a","auth_token":"s","relay_prefix":"myproxy"}'

echo "Prism Linux test runner  (PY=$PY  PORT=$PORT  live=$LIVE)"
$PY --version 2>&1 | sed 's/^/  /'

# ==========================================================================
sec "G -- CLI plumbing"
$PY -m prism --help >/dev/null 2>&1 && ok "G-01 --help renders" || no "G-01 --help"
$PY -m prism >/dev/null 2>&1; [ $? -eq 2 ] && ok "G-02 no subcommand -> exit 2" || no "G-02 no subcommand"
$PY -m prism bogus >/dev/null 2>&1; [ $? -eq 2 ] && ok "G-03 bad subcommand -> exit 2" || no "G-03 bad subcommand"
_g6=1; for c in init up down list test status; do $PY -m prism "$c" --help >/dev/null 2>&1 || _g6=0; done
[ "$_g6" = 1 ] && ok "G-06 every subcommand --help" || no "G-06 subcommand help"
$PY - <<'PYEOF' >/dev/null 2>&1 && ok "G-04/05 --debug on either side of subcommand" || no "G-04/05 --debug placement"
import prism, sys
p = prism.build_parser()
a = getattr(p.parse_args(['--debug','list']), 'debug', False)
b = getattr(p.parse_args(['list','--debug']), 'debug', False)
c = getattr(p.parse_args(['list']), 'debug', False)
sys.exit(0 if (a and b and not c) else 1)
PYEOF

# ==========================================================================
sec "S -- status states"
rm -f prism.json endpoints.json
$PY -m prism status 2>&1 | grep -q "MISSING"    && ok "S-01 no config"        || no "S-01 no config"
echo '{"provider":"cloudflare"}' > prism.json
$PY -m prism status 2>&1 | grep -q "INCOMPLETE" && ok "S-02 incomplete config" || no "S-02 incomplete"
echo "$CFG_CF" | $PY -c 'import sys,json;json.dump({**json.load(sys.stdin),"relay_prefix":"p"},open("prism.json","w"))'
$PY -m prism status 2>&1 | grep -q "present"     && ok "S-03 complete config"  || no "S-03 complete"
echo '[{"url":"https://a","name":"a"}]' > endpoints.json
$PY -m prism status 2>&1 | grep -q "1 deployed"  && ok "S-05 endpoint count"   || no "S-05 endpoint count"
rm -f endpoints.json

# ==========================================================================
sec "I -- init (flags + piped wizard)"
rm -f prism.json
# I-04-style: non-interactive via flags (api_token is a secret prompt, so a
# pipe can't drive it -- flags are how you script CF setup)
$PY -m prism init --provider cloudflare --api-token TKN --account-id ACC \
    --auth-token SEC --relay-prefix myproxy --force >/dev/null 2>&1
{ [ -f prism.json ] && grep -q '"cloudflare"' prism.json && grep -q '"TKN"' prism.json; } \
  && ok "I-04 non-interactive CF init" || no "I-04 flag init"
# I-02: refuse to overwrite complete config without --force
$PY -m prism init </dev/null 2>&1 | grep -q "already exists" && ok "I-02 refuse without --force" || no "I-02 refuse"
# I-01/I-15: piped wizard on the non-secret GCP path (provider, project, region,
# auth, prefix -- all Enter-able); secret prompts (CF token) need a real TTY.
rm -f prism.json
printf '2\n\n\n\n\n' | $PY -m prism init >/dev/null 2>&1
{ [ -f prism.json ] && grep -q '"gcp"' prism.json && grep -q 'us-central1' prism.json; } \
  && ok "I-01/I-15 piped GCP wizard + defaults" || no "I-01/I-15 piped wizard"
if have expect; then sk "I-11/I-12/I-13 (secret/validation prompts)" "add an expect script to cover TTY-only prompts"; \
  else sk "I-11/I-12/I-13 (secret/validation prompts)" "install 'expect' to drive TTY-only prompts"; fi

# ==========================================================================
sec "U -- up guards (no deploy)"
echo "$CFG_CF" | $PY -c 'import sys,json;json.dump(json.load(sys.stdin),open("prism.json","w"))'
rm -f endpoints.json
# U-03: the count guard. Pin a known-free --port so `up`'s port check (which
# runs first) can't fire ahead of the count validation we're actually testing.
$PY -m prism up --count 9 --port "$(free_port)" </dev/null 2>&1 | grep -q "between 1 and 6" && ok "U-03 --count out of range" || no "U-03 count range"
# U-05: port already in use -> exits before deploying. Use its own dedicated
# port so the holder's TIME_WAIT can't bleed into the live-phase rotator port.
P5="$(free_port)"
"$PY" - "$P5" >/dev/null 2>&1 <<'PYEOF' &
import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0)
s.bind(("0.0.0.0",int(sys.argv[1]))); s.listen(); time.sleep(8)
PYEOF
HOLD=$!; sleep 1
$PY -m prism up --port "$P5" --count 2 </dev/null 2>&1 | grep -q "already in use" && ok "U-05 port in use" || no "U-05 port in use"
kill "$HOLD" 2>/dev/null; wait "$HOLD" 2>/dev/null

sec "N -- new features (impersonation / opsec)"
# Offline logic suite: rotator impersonate/upstream_proxy knobs + coherence,
# relay _fetch (strip/fallback) on GCP+Azure, worker.js header hygiene.
if $PY "$ROOT/tests/test_new_features.py" >.nf.out 2>&1; then
  ok "N-00 offline feature suite ($(grep -c '\[PASS\]' .nf.out) checks)"
else
  no "N-00 offline feature suite" "failures below"; sed 's/^/      /' .nf.out
fi
rm -f .nf.out
# CLI/UX surface for the features
{ $PY -m prism --no-banner status >/dev/null 2>&1 && $PY -m prism status --no-banner >/dev/null 2>&1; } \
  && ok "N-01 --no-banner accepted before and after subcommand" || no "N-01 --no-banner"
{ $PY -m prism init --help 2>&1 | grep -q "^Cloudflare:" && $PY -m prism init --help 2>&1 | grep -q "^Azure:"; } \
  && ok "N-02 init --help grouped by provider" || no "N-02 init help groups"
$PY -m prism --help 2>&1 | grep -qi "httpx" \
  && no "N-03 httpx removed from usage text" "still present" || ok "N-03 httpx removed from usage text"
{ $PY -m prism --help 2>&1 | grep -q "TeamFiltration" && $PY -m prism --help 2>&1 | grep -q "proxyEndpoint"; } \
  && ok "N-04 TeamFiltration documented in usage" || no "N-04 TeamFiltration usage"
$PY -m prism test --help 2>&1 | grep -q -- "--fingerprint" \
  && ok "N-05 test --fingerprint flag present" || no "N-05 fingerprint flag"
[ "$($PY -m prism --help 2>&1 | grep -c "$(printf '\033')")" = "0" ] \
  && ok "N-06 no ANSI in piped --help (banner/splash TTY-gated)" || no "N-06 ANSI leak in piped help"

# ==========================================================================
if [ "$LIVE" = 0 ]; then
  sec "LIVE phase skipped"
  echo "  Re-run with --live to exercise deploy/rotate/teardown + the POSIX-only"
  echo "  paths (curl -x, HTTP_PROXY, SIGINT confirm prompt, proxychains SOCKS5)."
  echo "  It uses your real prism.json (restored afterward) and DEPLOYS billable relays."
else
  # restore the user's real config for the live run
  cp "$BAK/prism.json" prism.json 2>/dev/null || { echo "  no configured provider -- run 'prism init' first"; }
  PROVIDER="$($PY -c 'import json;print(json.load(open("prism.json")).get("provider","?"))' 2>/dev/null)"
  sec "LIVE lifecycle -- provider: $PROVIDER"
  for t in "$PY" curl; do have "${t%% *}" || true; done
  have curl || { no "live phase" "curl not found"; }

  rm -f endpoints.json
  echo "  [*] deploying 2 relays (this can take minutes on GCP/Azure)..."
  $PY -c 'import prism; from prism import relay_common as rc; prism.ensure_endpoints(rc.load_config(),2,True)' 2>&1 | sed 's/^/    /'
  N=$($PY -c 'import json;print(len(json.load(open("endpoints.json"))))' 2>/dev/null || echo 0)
  [ "$N" -ge 1 ] && ok "P-$PROVIDER deploy ($N relays)" || no "deploy" "no endpoints"

  $PY -m prism list 2>&1 | grep -q "relay-" && ok "L-01 list" || no "L-01 list"
  $PY -m prism test 2>&1 | grep -q "HTTP 200" && ok "T-01 canary" || no "T-01 canary"

  # F -- TLS fingerprint reporting (live check for the impersonate feature).
  # Routes a canary through each relay to a JA-echo service; with impersonate on
  # (and a curl_cffi redeploy) a GCP/Azure relay should report a browser JA4+UA.
  IMPERSONATE="$($PY -c 'import json;print(str(json.load(open("prism.json")).get("impersonate",False)).lower())' 2>/dev/null)"
  FP="$($PY -m prism test --fingerprint 2>&1)"
  echo "$FP" | grep -q "JA4 " && ok "F-01 test --fingerprint reports a JA4 per relay" || no "F-01 fingerprint report" "no JA4 line (echo service reachable?)"
  if [ "$IMPERSONATE" = "true" ] && [ "$PROVIDER" != "cloudflare" ]; then
    { echo "$FP" | grep -Eq "JA4 t13d.*h2" && echo "$FP" | grep -Eqi "chrome|safari|edg|firefox"; } \
      && ok "F-02 impersonate on -> relay presents a browser JA4 + UA" \
      || { no "F-02 browser fingerprint" "impersonate=true but relay JA4/UA not browser-like -- did you 'up --redeploy' after enabling?"; echo "$FP" | sed 's/^/      /'; }
  else
    sk "F-02 browser-fingerprint check" "set impersonate=true in prism.json (+ up --redeploy) on GCP/Azure to exercise"
  fi

  # start the rotator via the real `up` command (HTTP mode), in its own session,
  # with a FIFO on stdin so we can answer the Ctrl+C confirm prompt.
  MITM="$($PY -c 'import prism;print(prism.find_mitmdump() or "")')"
  if [ -z "$MITM" ]; then
    sk "rotator tests" "mitmdump not installed (pip install -r requirements.txt)"
  else
    kill_port "$PORT"   # clear any orphan before we bind
    rm -f .prism_ctl; mkfifo .prism_ctl
    $PY -m prism up --keep --port "$PORT" >.prism_up.out 2>&1 <.prism_ctl &
    UPPID=$!
    exec 3>.prism_ctl   # hold the FIFO open
    if wait_for "Starting rotator" .prism_up.out 200; then
      MITMPID="$(pgrep -f "mitmdump -s rotator_addon.py" | head -1)"
      wait_port "$PORT"   # don't curl until mitmdump has actually bound the port
      ok "up starts rotator on :$PORT"
      # -k on the proxied requests: the rotator is mitmproxy, which terminates
      # TLS locally with its own CA, so a client that hasn't installed that CA
      # (a fresh test box) must skip verification. We're checking egress IP, not
      # cert validity. The direct REAL= probe keeps verification on (real cert).
      REAL="$(curl -s https://api.ipify.org 2>/dev/null)"
      VIA="$(curl -sk -x "http://127.0.0.1:$PORT" https://api.ipify.org 2>/dev/null)"
      { [ -n "$VIA" ] && [ "$VIA" != "$REAL" ]; } \
        && ok "X-04/K-01 curl -x egresses via relay ($VIA != real $REAL)" \
        || no "X-04/K-01 curl -x" "via=$VIA real=$REAL"
      VIAENV="$(HTTP_PROXY="http://127.0.0.1:$PORT" HTTPS_PROXY="http://127.0.0.1:$PORT" curl -sk https://api.ipify.org 2>/dev/null)"
      { [ -n "$VIAENV" ] && [ "$VIAENV" != "$REAL" ]; } \
        && ok "X-04/K-03 HTTP_PROXY env egresses via relay" || no "HTTP_PROXY env" "got $VIAENV"
      if [ "$PROVIDER" = "cloudflare" ]; then
        LEAK="$(curl -sk -x "http://127.0.0.1:$PORT" https://httpbin.org/ip 2>/dev/null)"
        echo "$LEAK" | grep -q "$REAL" \
          && printf '  \033[33m[NOTE]\033[0m Cloudflare XFF leak confirmed: target saw your real IP (%s) in X-Forwarded-For\n' "$REAL" \
          || echo "  [NOTE] no XFF leak seen this run (target may not echo XFF)"
      fi
      # U-14: SIGINT then 'n' -> stays up. Wait for the confirm PROMPT before
      # answering so we never race ahead of it, and bound every wait so a
      # misbehaving prompt can never hang the whole suite.
      kill -INT "$UPPID" 2>/dev/null
      if wait_for "Are you sure" .prism_up.out 60; then
        echo "n" >&3
        wait_for "Staying up" .prism_up.out 60 && ok "U-14 Ctrl+C then n stays up" || no "U-14 stay up"
      else
        no "U-14 stay up" "no confirm prompt after SIGINT"
      fi
      # U-15/U-17: SIGINT then 'y' -> shuts down; --keep leaves relays
      kill -INT "$UPPID" 2>/dev/null
      wait_for "Are you sure" .prism_up.out 60 && echo "y" >&3
      # bounded wait for `up` to exit -- never a blind `wait` that can hang
      i=0; while [ "$i" -lt 40 ] && kill -0 "$UPPID" 2>/dev/null; do sleep 0.25; i=$((i+1)); done
      kill -0 "$UPPID" 2>/dev/null && kill "$UPPID" 2>/dev/null
      grep -q "Shutting down" .prism_up.out && ok "U-15 Ctrl+C then y shuts down" || no "U-15 shutdown"
      grep -q "keep given, leaving" .prism_up.out && ok "U-17 --keep left relays" || no "U-17 --keep"
    else
      no "up starts rotator" "no 'Starting rotator' within 20s (see .prism_up.out)"
    fi
    exec 3>&- 2>/dev/null; rm -f .prism_ctl
    [ -n "${MITMPID:-}" ] && kill "$MITMPID" 2>/dev/null
    kill_port "$PORT"; UPPID=""; MITMPID=""

    # SOCKS5 + proxychains (K-07 mechanism)
    if have proxychains4 || have proxychains; then
      PC="$(command -v proxychains4 || command -v proxychains)"
      kill_port "$PORT"   # clear any orphan before we re-bind
      $PY -m prism up --socks5 --keep --port "$PORT" >.prism_up.out 2>&1 </dev/null &
      UPPID=$!
      if wait_for "SOCKS5 mode" .prism_up.out 200; then
        MITMPID="$(pgrep -f "mitmdump -s rotator_addon.py" | head -1)"
        wait_port "$PORT"   # wait for the SOCKS5 listener to actually bind
        CONF="$(mktemp "${TMPDIR:-/tmp}/prism.XXXXXX")"; printf 'strict_chain\n[ProxyList]\nsocks5 127.0.0.1 %s\n' "$PORT" > "$CONF"
        SVIA="$(proxychains4 -f "$CONF" curl -sk https://api.ipify.org 2>/dev/null || "$PC" -f "$CONF" curl -sk https://api.ipify.org 2>/dev/null)"
        { [ -n "$SVIA" ] && [ "$SVIA" != "$REAL" ]; } \
          && ok "U-13/K-07 SOCKS5 via proxychains egresses via relay ($SVIA)" \
          || no "U-13/K-07 proxychains socks5" "got $SVIA"
        rm -f "$CONF"
      else
        no "up --socks5" "no 'SOCKS5 mode' banner"
      fi
      kill "$UPPID" 2>/dev/null
      [ -n "${MITMPID:-}" ] && kill "$MITMPID" 2>/dev/null
      pkill -f "mitmdump -s rotator_addon.py" 2>/dev/null
      kill_port "$PORT"; UPPID=""; MITMPID=""
    else
      sk "U-13/K-07 SOCKS5 + proxychains" "proxychains4 not installed"
    fi
  fi

  # teardown + verify
  echo "n" | $PY -m prism down >/dev/null 2>&1
  $PY -m prism list 2>&1 | grep -qiE "no deployed|no .* Workers|no .* Functions" && ok "D-01/D-05 teardown clean (nothing deployed)" || no "teardown" "relays may remain -- check 'prism list'"
fi

# ==========================================================================
sec "Summary"
printf '  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d skipped\033[0m\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
