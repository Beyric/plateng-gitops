#!/usr/bin/env bash
# End-to-end test of platform/monitoring/loki-rules-withdrawals.yaml against a real Loki
# (same version as the cluster) and a real Alertmanager, in Docker. ~2 minutes.
# Pushes api-worker / api style log lines (loguru prefix + JSON, as logged by
# app/worker/handlers/withdrawals.py) backdated over the last hour, lets the ruler
# evaluate, then checks rule state, value and delivery.
#   bash platform/monitoring/tests/loki-rules-withdrawals-test.sh      (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../../.."
LOKI_IMAGE=${LOKI_IMAGE:-grafana/loki:3.6.11}
AM_IMAGE=${AM_IMAGE:-quay.io/prometheus/alertmanager:v0.28.1}
SCENARIOS="unresolved refunded fromapi expired noise"
W=$(mktemp -d); NET=loki-rules-wd-test-$$
cleanup(){ docker rm -f lrd-am-$$ $(for s in $SCENARIOS; do echo lrd-$s-$$; done) >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/rules/fake"
python3 - "$W/rules/fake/withdrawals.yaml" <<'PY'
import yaml,sys
cm=yaml.safe_load(open('platform/monitoring/loki-rules-withdrawals.yaml'))
open(sys.argv[1],'w').write(cm['data']['withdrawals.yaml'])
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
docker run -d --name lrd-am-$$ --network $NET --network-alias am -p 127.0.0.1::9093 -v "$W/am.yaml:/etc/am.yaml:ro" $AM_IMAGE --config.file=/etc/am.yaml >/dev/null
for s in $SCENARIOS; do
  docker run -d --name lrd-$s-$$ --network $NET -p 127.0.0.1::3100 -v "$W/loki.yaml:/etc/loki.yaml:ro" -v "$W/rules:/rules:ro" $LOKI_IMAGE -config.file=/etc/loki.yaml >/dev/null
done
port(){ docker port "$1" "$2" | head -1 | cut -d: -f2; }
for s in $SCENARIOS; do
  p=$(port lrd-$s-$$ 3100); for i in $(seq 1 60); do curl -sf "http://127.0.0.1:$p/ready" >/dev/null && break; sleep 2; done
  python3 - "$s" "$p" <<'PY'
import json,sys,time,urllib.request
scenario,port=sys.argv[1],sys.argv[2]
now=time.time(); streams={}
def line(t,msg,level="INFO    ",src="logging:callHandlers:1706"):
    ts=time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(t))+".000"
    return [str(int(t*1e9)),f"{ts} | {level} | {src} - {msg}"]
def event(t,name,wid="00000000-0000-0000-0000-00000000000a"):
    # json.dumps default separators, exactly like withdrawals.py; ids are placeholders
    level="ERROR   " if name=="withdrawal_unresolved" else "WARNING "
    return line(t,json.dumps({"event":name,"withdrawal_id":wid}),level)
for m in range(60,-1,-1):                      # worker heartbeat + api health noise for an hour
    streams.setdefault("api-worker",[]).append(line(now-m*60,json.dumps({"event":"jobs_stats","pending":0,"oldest_overdue_pending_seconds":None,"dead":0,"disabled_kinds":[]})))
    streams.setdefault("api",[]).append(line(now-m*60,"GET /api/v1/health completed in 0.0011s with status 200","INFO    ","app.main:logging_middleware:83"))
if scenario=="unresolved": streams["api-worker"].append(event(now-2*60,"withdrawal_unresolved"))
if scenario=="refunded":   streams["api-worker"]+= [event(now-10*60,"withdrawal_refunded_by_recheck"), event(now-60,"withdrawal_refunded_by_recheck","00000000-0000-0000-0000-00000000000b")]
if scenario=="fromapi":    streams["api"].append(event(now-60,"withdrawal_unresolved"))
if scenario=="expired":    streams["api-worker"]+= [event(now-45*60,"withdrawal_unresolved"), event(now-40*60,"withdrawal_refunded_by_recheck")]
if scenario=="noise":      # same words, not the event: the plain-text refund line and the failed-alert exception
    streams["api-worker"]+= [line(now-60,"[WITHDRAWAL RECHECK] wys_withdraw_00000000-0000-0000-0000-00000000000a was not sent; refunded","WARNING "),
                             line(now-60,"[WITHDRAWAL RECHECK] could not raise the withdrawal_unresolved alert for 00000000-0000-0000-0000-00000000000a","ERROR   "),
                             line(now-60,json.dumps({"event":"wallet_lot_drift","users":1}),"ERROR   ")]
for v in streams.values(): v.sort()
body={"streams":[{"stream":{"namespace":"weysure-prod","container":c,"pod":c+"-x"},"values":v} for c,v in streams.items()]}
req=urllib.request.Request(f"http://127.0.0.1:{port}/loki/api/v1/push",data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
urllib.request.urlopen(req).read(); print(f"  {scenario}: pushed {sum(len(v) for v in streams.values())} lines")
PY
done
echo "waiting for the ruler (no for:, so firing on the first evaluation) ..."
state(){ curl -s "http://127.0.0.1:$(port lrd-$1-$$ 3100)/prometheus/api/v1/rules" | python3 -c "
import json,sys
out=[]
for g in json.load(sys.stdin)['data']['groups']:
    for r in g['rules']:
        v=' '.join(a['value'] for a in r.get('alerts',[]))
        out.append(f\"{r['name']}={r['state']}\"+(f'({float(v):g})' if v else ''))
print(' '.join(out))"; }
want_unresolved="WithdrawalUnresolved=firing(1) WithdrawalRefundedByRecheck=inactive"
want_refunded="WithdrawalUnresolved=inactive WithdrawalRefundedByRecheck=firing(2)"
want_fromapi="WithdrawalUnresolved=firing(1) WithdrawalRefundedByRecheck=inactive"
want_expired="WithdrawalUnresolved=inactive WithdrawalRefundedByRecheck=inactive"
want_noise="WithdrawalUnresolved=inactive WithdrawalRefundedByRecheck=inactive"
for i in $(seq 1 18); do
  ok=1; for s in $SCENARIOS; do w=want_$s; [[ "$(state $s)" == "${!w}" ]] || ok=0; done
  [[ $ok == 1 ]] && break; sleep 10
done
fail=0
for s in $SCENARIOS; do got=$(state $s); w=want_$s; if [[ "$got" == "${!w}" ]]; then echo "PASS $s: $got"; else echo "FAIL $s: got '$got', want '${!w}'"; fail=1; fi; done
recv=$(curl -s "http://127.0.0.1:$(port lrd-am-$$ 9093)/api/v2/alerts" | python3 -c "import json,sys; print(' '.join(sorted(f\"{a['labels']['alertname']}/{a['labels']['severity']}\" for a in json.load(sys.stdin))))")
# unresolved + fromapi carry the same labels (sum() drops stream labels), so Alertmanager
# holds them as ONE alert: one page per alert name, not one per container or withdrawal.
want_recv="WithdrawalRefundedByRecheck/warning WithdrawalUnresolved/critical"
if [[ "$recv" == "$want_recv" ]]; then echo "PASS alertmanager received: $recv"; else echo "FAIL alertmanager received: '$recv', want '$want_recv'"; fail=1; fi
exit $fail
