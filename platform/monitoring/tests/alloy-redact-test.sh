#!/usr/bin/env bash
# Test of the loki.process "redact" block in bootstrap/apps/alloy.yaml against a real
# Alloy (same version as the cluster) in Docker. ~30 seconds.
# The block is cut from the Argo Application as-is, fed by loki.source.api and printed
# by loki.echo; test lines are pushed over HTTP and the echoed lines are checked.
# Every secret below is fake. Decoys share the words but must come out unchanged.
#   bash platform/monitoring/tests/alloy-redact-test.sh      (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../../.."
ALLOY_IMAGE=${ALLOY_IMAGE:-grafana/alloy:v1.19.2}
W=$(mktemp -d); C=alloy-redact-test-$$; PORT=${PORT:-13500}
cleanup(){ docker rm -f $C >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT

python3 - "$W" <<'PY'
import re, sys, yaml
app = yaml.safe_load(open('bootstrap/apps/alloy.yaml'))
content = app['spec']['source']['helm']['valuesObject']['alloy']['configMap']['content']
open(f'{sys.argv[1]}/full.alloy', 'w').write(content)
start = content.index('loki.process "redact" {')
depth, i = 0, start
while True:                       # cut the block by brace matching
    if content[i] == '{': depth += 1
    elif content[i] == '}':
        depth -= 1
        if depth == 0: break
    i += 1
block = content[start:i + 1]
block = re.sub(r'forward_to\s*=\s*\[[^\]]*\]', 'forward_to = [loki.echo.out.receiver]', block, count=1)
open(f'{sys.argv[1]}/test.alloy', 'w').write(f'''logging {{ level = "info" }}
loki.source.api "in" {{
  http {{
    listen_address = "0.0.0.0"
    listen_port    = 3500
  }}
  forward_to = [loki.process.redact.receiver]
}}
{block}
loki.echo "out" {{ }}
''')
PY

echo "== alloy fmt (full cluster config)"
docker run --rm -v "$W:/w:ro" "$ALLOY_IMAGE" fmt /w/full.alloy >/dev/null && echo "valid"

docker run -d --name $C -p "$PORT:3500" -v "$W:/w:ro" "$ALLOY_IMAGE" run /w/test.alloy >/dev/null
for _ in $(seq 1 30); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/ready" && break; sleep 1; done

# A fake, JWT-shaped invite token built at run time (no token literal in git; gitleaks).
b64url(){ printf '%s' "$1" | base64 | tr -d '=\n' | tr '/+' '_-'; }
JWT="$(b64url '{"alg":"HS256","typ":"JWT"}').$(b64url '{"sub":"FAKE-INVITE","typ":"deal_invite"}').FAKESIGFAKESIGFAKESIG"
# name | input line | must contain | must NOT contain
CASES=$(cat <<EOF
api-jwt-preview|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "GET /api/v1/invites/$JWT HTTP/2.0" 200 512 "-" "-" 1 "websecure-weysure-prod-api-api-weysure-com@kubernetes" "http://10.0.0.1:8000" 5ms|GET /api/v1/invites/{token} HTTP/2.0|eyJ
api-opaque-claim|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "POST /api/v1/invites/OPAQUESECRET01/claim HTTP/2.0" 200 64 "-" "-" 2 "r@kubernetes" "http://10.0.0.1:8000" 5ms|POST /api/v1/invites/{token}/claim HTTP|OPAQUESECRET01
api-opaque-decline-query|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "POST /api/v1/invites/OPAQUESECRET02/decline?x=1 HTTP/2.0" 200 64|/api/v1/invites/{token}/decline?x=1|OPAQUESECRET02
web-page-rsc|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "GET /invite/OPAQUESECRET03?_rsc=abc HTTP/2.0" 200 9000 "-" "-" 3 "websecure-weysure-prod-web-weysure-com@kubernetes" "http://10.0.0.2:3000" 9ms|GET /invite/{token}?_rsc=abc|OPAQUESECRET03
referer|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "GET /api/v1/escrow/123 HTTP/2.0" 200 10 "https://weysure.com/invite/OPAQUESECRET04" "Mozilla" 4 "r@kubernetes"|https://weysure.com/invite/{token}|OPAQUESECRET04
json-app-line|{"level":"info","path":"/api/v1/invites/OPAQUESECRET05","status":404}|"path":"/api/v1/invites/{token}"|OPAQUESECRET05
already-templated|[INFO] "GET /api/v1/invites/{token} HTTP/1.1" 200|GET /api/v1/invites/{token} HTTP/1.1|{token}}
ws-jwt-regression|"GET /api/v1/ws/messages?token=$JWT HTTP/1.1" 101|?token=<redacted-jwt> HTTP|eyJ
decoy-create|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "POST /api/v1/escrow/invites HTTP/2.0" 201 300|POST /api/v1/escrow/invites HTTP/2.0|{token}
decoy-resend|1.2.3.4 - - [16/Oct/2026:10:00:00 +0000] "POST /api/v1/escrow/invites/DECOYID0001/resend HTTP/2.0" 200 30|/api/v1/escrow/invites/DECOYID0001/resend|{token}
decoy-bare-list|"GET /api/v1/invites/ HTTP/2.0" 404|GET /api/v1/invites/ HTTP/2.0|{token}
decoy-word|invite.send job done for invite_id=DECOYID0002 (invites/ in text)|invite_id=DECOYID0002 (invites/ in text)|{token}
cookie-request-header|1.2.3.4 - - [30/Oct/2026:10:00:00 +0000] "POST /api/v1/auth/refresh HTTP/2.0" 200 40 "-" "Cookie: wey_rt=FAKECOOKIE01; wey_did=FAKECOOKIE02; other=FAKECOOKIE03" 1|Cookie: <redacted-cookie>|FAKECOOKIE
cookie-set-cookie|response headers Set-Cookie: wey_at=FAKECOOKIE04; Path=/api/v1; HttpOnly; Secure; SameSite=Strict|Set-Cookie: <redacted-cookie>|FAKECOOKIE
cookie-kv-in-text|request carried wey_mfa=FAKECOOKIE05 and was rejected|wey_mfa=<redacted-cookie> and was rejected|FAKECOOKIE
cookie-dict-repr|cookies={'wey_art': 'FAKECOOKIE06', 'other': 'x'}|'wey_art': '<redacted-cookie>'|FAKECOOKIE
cookie-json-header|{"level":"info","cookie":"wey_rt=FAKECOOKIE07"}|"cookie":"<redacted-cookie>"|FAKECOOKIE
decoy-cookie-setting|[INFO] REFRESH_COOKIE_SECURE=true ACCESS_COOKIE_MODE=dual|REFRESH_COOKIE_SECURE=true ACCESS_COOKIE_MODE=dual|<redacted-cookie>
decoy-cookie-words|refresh cookie rotated; wey_did_lookup=DECOYCOOKIE08 for wey_at name only|wey_did_lookup=DECOYCOOKIE08 for wey_at name only|<redacted-cookie>
EOF
)

now=$(date +%s)
python3 - "$now" "$CASES" > "$W/push.json" <<'PY'
import json, sys
now = int(sys.argv[1]); vals = []
for n, line in enumerate(sys.argv[2].splitlines()):
    name, inp = line.split('|')[:2]          # fields are '|'-separated; no input contains '|'
    vals.append([str((now + n) * 10**9), f'CASE={name} {inp}'])
print(json.dumps({"streams": [{"stream": {"namespace": "test"}, "values": vals}]}))
PY
curl -sf -X POST -H 'Content-Type: application/json' --data @"$W/push.json" "http://127.0.0.1:$PORT/loki/api/v1/push"
sleep 3
docker logs $C 2>&1 | command grep 'loki.echo' > "$W/out.log" || true

python3 - "$W/out.log" "$CASES" <<'PY'
import re, sys
raw = open(sys.argv[1]).read()
# loki.echo prints entry="<line>" with Go %q escaping; undo the escaping of quotes/backslashes.
entries = {}
for m in re.finditer(r'entry="((?:[^"\\]|\\.)*)"', raw):
    e = m.group(1).encode().decode('unicode_escape')
    k = re.match(r'CASE=(\S+) ', e)
    if k: entries[k.group(1)] = e
fails = 0
for line in sys.argv[2].splitlines():
    name, _inp, want, deny = line.split('|')
    out = entries.get(name)
    ok = out is not None and want in out and deny not in out
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name}" + ('' if ok else f"\n     got: {out}\n    want: {want!r}  deny: {deny!r}"))
print(f"{len(sys.argv[2].splitlines()) - fails}/{len(sys.argv[2].splitlines())} passed")
sys.exit(1 if fails else 0)
PY
