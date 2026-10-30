#!/usr/bin/env bash
# End-to-end test of platform/monitoring/loki-rules-autopause.yaml against a real Loki
# (same version as the cluster) and a real Alertmanager, in Docker. ~2 minutes.
# Pushes api-worker / api style log lines (loguru prefix, as logged by app/services/live_pause.py,
# live_auto_pause.py and the worker handler) backdated over the last hour, lets the ruler
# evaluate, then checks rule state, value and delivery. Decoys share the words, not the event.
#   bash platform/monitoring/tests/loki-rules-autopause-test.sh      (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../../.."
LOKI_IMAGE=${LOKI_IMAGE:-grafana/loki:3.6.11}
AM_IMAGE=${AM_IMAGE:-quay.io/prometheus/alertmanager:v0.28.1}
SCENARIOS="paused two failed sweepfail fromapi shadow expired"
W=$(mktemp -d); NET=loki-rules-ap-test-$$
cleanup(){ docker rm -f lra-am-$$ $(for s in $SCENARIOS; do echo lra-$s-$$; done) >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/rules/fake"
python3 - "$W/rules/fake/autopause.yaml" <<'PY'
import yaml,sys
cm=yaml.safe_load(open('platform/monitoring/loki-rules-autopause.yaml'))
open(sys.argv[1],'w').write(cm['data']['autopause.yaml'])
PY
cat > "$W/loki.yaml" <<'YAML'
auth_enabled: false
server: { http_listen_port: 3100, log_level: warn }
common:
  path_prefix: /tmp/loki
  replication_factor: 1
  ring: { kvstore: { store: inmemory } }
  storage: { filesystem: { chunks_directory: /tmp/loki/chunks, rules_directory: /tmp/loki/unused } }
schema_config:
  configs: [{ from: "2020-01-01", store: tsdb, object_store: filesystem, schema: v13, index: { prefix: index_, period: 24h } }]
limits_config: { reject_old_samples: false }
ruler:
  wal: { dir: /tmp/loki/ruler-wal }
  storage: { type: local, local: { directory: /rules } }
  rule_path: /tmp/loki/rules-scratch
  alertmanager_url: http://am:9093
  enable_api: true
  evaluation_interval: 1m
YAML
printf 'route: { receiver: sink, group_wait: 1s }\nreceivers: [{ name: sink }]\n' > "$W/am.yaml"
docker network create $NET >/dev/null
docker run -d --name lra-am-$$ --network $NET --network-alias am -p 127.0.0.1::9093 -v "$W/am.yaml:/etc/am.yaml:ro" $AM_IMAGE --config.file=/etc/am.yaml >/dev/null
for s in $SCENARIOS; do
  docker run -d --name lra-$s-$$ --network $NET -p 127.0.0.1::3100 -v "$W/loki.yaml:/etc/loki.yaml:ro" -v "$W/rules:/rules:ro" $LOKI_IMAGE -config.file=/etc/loki.yaml >/dev/null
done
port(){ docker port "$1" "$2" | head -1 | cut -d: -f2; }
for s in $SCENARIOS; do
  p=$(port lra-$s-$$ 3100); for i in $(seq 1 60); do curl -sf "http://127.0.0.1:$p/ready" >/dev/null && break; sleep 2; done
  python3 - "$s" "$p" <<'PY'
import json,sys,time,urllib.request
scenario,port=sys.argv[1],sys.argv[2]
now=time.time(); streams={}
UID1="WS0000000000-aaaaaaaa"; UID2="WS0000000001-bbbbbbbb"   # placeholders
def line(t,msg,level="INFO    ",src="app.worker.handlers.live_auto_pause:run:28"):
    ts=time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(t))+".000"
    return [str(int(t*1e9)),f"{ts} | {level} | {src} - {msg}"]
for m in range(60,-1,-1):                      # worker heartbeat + api health noise for an hour
    streams.setdefault("api-worker",[]).append(line(now-m*60,json.dumps({"event":"jobs_stats","pending":0,"dead":0})))
    streams.setdefault("api",[]).append(line(now-m*60,"GET /api/v1/health completed in 0.0011s with status 200","INFO    ","app.main:logging_middleware:83"))
paused=lambda t,u: line(t,f"[LIVE AUTO PAUSE] paused live keys of {u}","WARNING ","app.services.live_pause:pause_system:126")
if scenario=="paused":    streams["api-worker"]+= [paused(now-2*60,UID1), line(now-2*60,"[LIVE AUTO PAUSE] 1 developer(s) tripped a rule","WARNING ")]
if scenario=="two":       streams["api-worker"]+= [paused(now-10*60,UID1), paused(now-60,UID2)]
if scenario=="failed":    streams["api-worker"].append(line(now-2*60,f"[LIVE AUTO PAUSE] failed for {UID1}: OperationalError","ERROR   ","app.services.live_auto_pause:sweep:200"))
if scenario=="sweepfail": streams["api-worker"].append(line(now-2*60,"[LIVE AUTO PAUSE] sweep failed: OperationalError","ERROR   "))
if scenario=="fromapi":   streams["api"].append(paused(now-60,UID1))
if scenario=="shadow":    # shadow mode pauses nothing; same prefix, not the event
    streams["api-worker"]+= [line(now-60,f"[LIVE AUTO PAUSE] shadow: would pause {UID1}: rules=['velocity']","WARNING ","app.services.live_auto_pause:sweep:177"),
                             line(now-60,"[LIVE AUTO PAUSE] 1 developer(s) tripped a rule","WARNING "),
                             line(now-60,"live.auto_pause_sweep rescheduled","INFO    ")]
if scenario=="expired":   streams["api-worker"]+= [paused(now-45*60,UID1), line(now-40*60,"[LIVE AUTO PAUSE] sweep failed: OperationalError","ERROR   ")]
for v in streams.values(): v.sort()
body={"streams":[{"stream":{"namespace":"weysure-prod","container":c,"pod":c+"-x"},"values":v} for c,v in streams.items()]}
req=urllib.request.Request(f"http://127.0.0.1:{port}/loki/api/v1/push",data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
urllib.request.urlopen(req).read(); print(f"  {scenario}: pushed {sum(len(v) for v in streams.values())} lines")
PY
done
echo "waiting for the ruler (no for:, so firing on the first evaluation) ..."
state(){ curl -s "http://127.0.0.1:$(port lra-$1-$$ 3100)/prometheus/api/v1/rules" | python3 -c "
import json,sys
out=[]
for g in json.load(sys.stdin)['data']['groups']:
    for r in g['rules']:
        v=' '.join(a['value'] for a in r.get('alerts',[]))
        out.append(f\"{r['name']}={r['state']}\"+(f'({float(v):g})' if v else ''))
print(' '.join(out))"; }
want_paused="LiveKeysAutoPaused=firing(1) LiveAutoPauseFailing=inactive"
want_two="LiveKeysAutoPaused=firing(2) LiveAutoPauseFailing=inactive"
want_failed="LiveKeysAutoPaused=inactive LiveAutoPauseFailing=firing(1)"
want_sweepfail="LiveKeysAutoPaused=inactive LiveAutoPauseFailing=firing(1)"
want_fromapi="LiveKeysAutoPaused=firing(1) LiveAutoPauseFailing=inactive"
want_shadow="LiveKeysAutoPaused=inactive LiveAutoPauseFailing=inactive"
want_expired="LiveKeysAutoPaused=inactive LiveAutoPauseFailing=inactive"
for i in $(seq 1 18); do
  ok=1; for s in $SCENARIOS; do w=want_$s; [[ "$(state $s)" == "${!w}" ]] || ok=0; done
  [[ $ok == 1 ]] && break; sleep 10
done
fail=0
for s in $SCENARIOS; do got=$(state $s); w=want_$s; if [[ "$got" == "${!w}" ]]; then echo "PASS $s: $got"; else echo "FAIL $s: got '$got', want '${!w}'"; fail=1; fi; done
recv=$(curl -s "http://127.0.0.1:$(port lra-am-$$ 9093)/api/v2/alerts" | python3 -c "import json,sys; print(' '.join(sorted(f\"{a['labels']['alertname']}/{a['labels']['severity']}\" for a in json.load(sys.stdin))))")
# sum() drops stream labels, so scenarios with the same alert name collapse to ONE alert in
# Alertmanager: one page per alert name, not one per developer or container.
want_recv="LiveAutoPauseFailing/critical LiveKeysAutoPaused/warning"
if [[ "$recv" == "$want_recv" ]]; then echo "PASS alertmanager received: $recv"; else echo "FAIL alertmanager received: '$recv', want '$want_recv'"; fail=1; fi
exit $fail
