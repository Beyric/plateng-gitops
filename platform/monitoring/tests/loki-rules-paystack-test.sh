#!/usr/bin/env bash
# End-to-end test of platform/monitoring/loki-rules-paystack.yaml against a real Loki
# (same version as the cluster) and a real Alertmanager, in Docker. ~2 minutes.
# Pushes api style log lines (loguru prefix, copied from real prod lines of image
# 28e48768d0cd) backdated over the last hour, lets the ruler evaluate, then checks
# rule state, value and delivery.
#   bash platform/monitoring/tests/loki-rules-paystack-test.sh      (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../../.."
LOKI_IMAGE=${LOKI_IMAGE:-grafana/loki:3.6.11}
AM_IMAGE=${AM_IMAGE:-quay.io/prometheus/alertmanager:v0.28.1}
SCENARIOS="mismatch sigfail sigone unavail expired noise"
W=$(mktemp -d); NET=loki-rules-ps-test-$$
cleanup(){ docker rm -f lrp-am-$$ $(for s in $SCENARIOS; do echo lrp-$s-$$; done) >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/rules/fake"
python3 - "$W/rules/fake/paystack.yaml" <<'PY'
import yaml,sys
cm=yaml.safe_load(open('platform/monitoring/loki-rules-paystack.yaml'))
open(sys.argv[1],'w').write(cm['data']['paystack.yaml'])
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
docker run -d --name lrp-am-$$ --network $NET --network-alias am -p 127.0.0.1::9093 -v "$W/am.yaml:/etc/am.yaml:ro" $AM_IMAGE --config.file=/etc/am.yaml >/dev/null
for s in $SCENARIOS; do
  docker run -d --name lrp-$s-$$ --network $NET -p 127.0.0.1::3100 -v "$W/loki.yaml:/etc/loki.yaml:ro" -v "$W/rules:/rules:ro" $LOKI_IMAGE -config.file=/etc/loki.yaml >/dev/null
done
port(){ docker port "$1" "$2" | head -1 | cut -d: -f2; }
for s in $SCENARIOS; do
  p=$(port lrp-$s-$$ 3100); for i in $(seq 1 60); do curl -sf "http://127.0.0.1:$p/ready" >/dev/null && break; sleep 2; done
  python3 - "$s" "$p" <<'PY'
import json,sys,time,urllib.request
scenario,port=sys.argv[1],sys.argv[2]
now=time.time(); streams={"api":[]}
def line(t,msg,level="INFO    ",src="app.main:logging_middleware:82"):
    ts=time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(t))+".000"
    return [str(int(t*1e9)),f"{ts} | {level} | {src} - {msg}"]
WH="app.api.v1.endpoints.wallet:_handle_paystack_webhook:"
def access(t,code,path="/api/v1/wallet/paystack/webhook",method="POST"):
    return line(t,f"{method} {path} completed in 0.3591s with status {code}")
def mismatch(t): return line(t,"paystack webhook: signature/mode mismatch event=charge.success flow=wallet_topup signed_by=developer_test","WARNING ","app.api.v1.endpoints.wallet:_refuse_untrusted:846")
def sigfail(t):  return line(t,"[PAYSTACK WEBHOOK] Signature verification failed","WARNING ",WH+"805")
api=streams["api"]
for m in range(60,-1,-1):                      # health noise + honest webhooks for an hour
    api.append(access(now-m*60,200,"/api/v1/health","GET"))
    api+= [line(now-m*60,"[PAYSTACK WEBHOOK] Signature verified, key class: developer_test,wallet",src=WH+"807"), access(now-m*60,200)]
if scenario=="mismatch": api.append(mismatch(now-2*60))
if scenario=="sigfail":  api+= [sigfail(now-k*60) for k in (1,5,9)]
if scenario=="sigone":   api.append(sigfail(now-60))
if scenario=="unavail":  api+= [access(now-k*60,503) for k in (1,4,7)]
if scenario=="expired":  api+= [mismatch(now-45*60)]+[sigfail(now-k*60) for k in (40,41,42)]+[access(now-k*60,503) for k in (40,41,42)]
if scenario=="noise":    # same words elsewhere: 503 on another path, webhook 400/500, other container
    api+= [access(now-k*60,503,"/api/v1/wallet/topup") for k in (1,2,3)]+[access(now-60,500),access(now-60,400)]
    streams["api-worker"]=[line(now-60,"paystack webhook: signature/mode mismatch event=x flow=y signed_by=z","WARNING ")]
for v in streams.values(): v.sort()
body={"streams":[{"stream":{"namespace":"weysure-prod","container":c,"pod":c+"-x"},"values":v} for c,v in streams.items()]}
req=urllib.request.Request(f"http://127.0.0.1:{port}/loki/api/v1/push",data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
urllib.request.urlopen(req).read(); print(f"  {scenario}: pushed {sum(len(v) for v in streams.values())} lines")
PY
done
echo "waiting for the ruler (no for:, so firing on the first evaluation) ..."
state(){ curl -s "http://127.0.0.1:$(port lrp-$1-$$ 3100)/prometheus/api/v1/rules" | python3 -c "
import json,sys
out=[]
for g in json.load(sys.stdin)['data']['groups']:
    for r in g['rules']:
        v=' '.join(a['value'] for a in r.get('alerts',[]))
        out.append(f\"{r['name']}={r['state']}\"+(f'({float(v):g})' if v else ''))
print(' '.join(out))"; }
want_mismatch="PaystackWebhookKeyMismatch=firing(1) PaystackWebhookSignatureFailing=inactive PaystackWebhookVerifyUnavailable=inactive"
want_sigfail="PaystackWebhookKeyMismatch=inactive PaystackWebhookSignatureFailing=firing(3) PaystackWebhookVerifyUnavailable=inactive"
want_sigone="PaystackWebhookKeyMismatch=inactive PaystackWebhookSignatureFailing=inactive PaystackWebhookVerifyUnavailable=inactive"
want_unavail="PaystackWebhookKeyMismatch=inactive PaystackWebhookSignatureFailing=inactive PaystackWebhookVerifyUnavailable=firing(3)"
want_expired="PaystackWebhookKeyMismatch=inactive PaystackWebhookSignatureFailing=inactive PaystackWebhookVerifyUnavailable=inactive"
want_noise="PaystackWebhookKeyMismatch=inactive PaystackWebhookSignatureFailing=inactive PaystackWebhookVerifyUnavailable=inactive"
for i in $(seq 1 18); do
  ok=1; for s in $SCENARIOS; do w=want_$s; [[ "$(state $s)" == "${!w}" ]] || ok=0; done
  [[ $ok == 1 ]] && break; sleep 10
done
fail=0
for s in $SCENARIOS; do got=$(state $s); w=want_$s; if [[ "$got" == "${!w}" ]]; then echo "PASS $s: $got"; else echo "FAIL $s: got '$got', want '${!w}'"; fail=1; fi; done
recv=$(curl -s "http://127.0.0.1:$(port lrp-am-$$ 9093)/api/v2/alerts" | python3 -c "import json,sys; print(' '.join(sorted(f\"{a['labels']['alertname']}/{a['labels']['severity']}\" for a in json.load(sys.stdin))))")
want_recv="PaystackWebhookKeyMismatch/critical PaystackWebhookSignatureFailing/warning PaystackWebhookVerifyUnavailable/warning"
if [[ "$recv" == "$want_recv" ]]; then echo "PASS alertmanager received: $recv"; else echo "FAIL alertmanager received: '$recv', want '$want_recv'"; fail=1; fi
exit $fail
