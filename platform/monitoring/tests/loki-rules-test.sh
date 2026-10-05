#!/usr/bin/env bash
# End-to-end test of platform/monitoring/loki-rules-jobs.yaml against a real Loki
# (same version as the cluster) and a real Alertmanager, in Docker. ~4 minutes.
# Pushes api-worker style log lines (loguru prefix + JSON) backdated over the last
# 20 minutes, lets the ruler evaluate, then checks rule state and delivery.
#   bash platform/monitoring/tests/loki-rules-test.sh      (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../../.."
LOKI_IMAGE=${LOKI_IMAGE:-grafana/loki:3.6.11}
AM_IMAGE=${AM_IMAGE:-quay.io/prometheus/alertmanager:v0.28.1}
W=$(mktemp -d); NET=loki-rules-test-$$
cleanup(){ docker rm -f lrt-am-$$ lrt-lag-$$ lrt-steady-$$ lrt-deadup-$$ lrt-podchange-$$ >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/rules/fake"
python3 - "$W/rules/fake/jobs.yaml" <<'PY'
import yaml,sys
cm=yaml.safe_load(open('platform/monitoring/loki-rules-jobs.yaml'))
open(sys.argv[1],'w').write(cm['data']['jobs.yaml'])
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
docker run -d --name lrt-am-$$ --network $NET --network-alias am -p 127.0.0.1::9093 -v "$W/am.yaml:/etc/am.yaml:ro" $AM_IMAGE --config.file=/etc/am.yaml >/dev/null
for s in lag steady deadup podchange; do
  docker run -d --name lrt-$s-$$ --network $NET -p 127.0.0.1::3100 -v "$W/loki.yaml:/etc/loki.yaml:ro" -v "$W/rules:/rules:ro" $LOKI_IMAGE -config.file=/etc/loki.yaml >/dev/null
done
port(){ docker port "$1" "$2" | head -1 | cut -d: -f2; }
for s in lag steady deadup podchange; do
  p=$(port lrt-$s-$$ 3100); for i in $(seq 1 60); do curl -sf "http://127.0.0.1:$p/ready" >/dev/null && break; sleep 2; done
  python3 - "$s" "$p" <<'PY'
import json,sys,time,urllib.request
scenario,port=sys.argv[1],sys.argv[2]
now=time.time(); streams={}
def S(dead,overdue=None): return {"pending":0,"oldest_overdue_pending_seconds":overdue,"dead":dead}
for m in range(20,-1,-1):                       # one stats line per minute, 20 min back to now
    if scenario=="lag":       pod,stats="a",S(0,400 if m<=8 else 0)
    if scenario=="steady":    pod,stats="a",S(2,None if m%3 else 30)          # sticky dead, mostly null lag
    if scenario=="deadup":    pod,stats="a",S(0 if m>3 else 1)
    if scenario=="podchange": pod,stats=("a",S(0)) if m>5 else ("b",S(1))      # replaced pod reports the increase
    t=now-m*60; ts=time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(t))+".000"
    v=streams.setdefault(pod,[])
    v.append([str(int(t*1e9)),f'{ts} | INFO     | logging:callHandlers:1706 - '+json.dumps({"event":"jobs_stats",**stats})])
    v.append([str(int(t*1e9)+1),f'{ts} | INFO     | app.main:logging_middleware:80 - GET /api/v1/health completed in 0.0011s with status 200'])
body={"streams":[{"stream":{"namespace":"weysure-prod","container":"api-worker","pod":p},"values":v} for p,v in streams.items()]}
vals=[x for v in streams.values() for x in v]
req=urllib.request.Request(f"http://127.0.0.1:{port}/loki/api/v1/push",data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
urllib.request.urlopen(req).read(); print(f"  {scenario}: pushed {len(vals)} lines")
PY
done
echo "waiting for the ruler (rule for: 2m + evaluation interval) ..."
state(){ curl -s "http://127.0.0.1:$(port lrt-$1-$$ 3100)/prometheus/api/v1/rules" | python3 -c "import json,sys; print(' '.join(f\"{r['name']}={r['state']}\" for g in json.load(sys.stdin)['data']['groups'] for r in g['rules']))"; }
want_lag="JobsQueueLagging=firing JobsDeadIncreased=inactive"
want_steady="JobsQueueLagging=inactive JobsDeadIncreased=inactive"
want_deadup="JobsQueueLagging=inactive JobsDeadIncreased=firing"
want_podchange="JobsQueueLagging=inactive JobsDeadIncreased=firing"
for i in $(seq 1 30); do
  a=$(state lag); b=$(state steady); c=$(state deadup); d=$(state podchange)
  [[ "$a" == "$want_lag" && "$b" == "$want_steady" && "$c" == "$want_deadup" && "$d" == "$want_podchange" ]] && break
  sleep 10
done
fail=0
for s in lag steady deadup podchange; do got=$(state $s); w=want_$s; if [[ "$got" == "${!w}" ]]; then echo "PASS $s: $got"; else echo "FAIL $s: got '$got', want '${!w}'"; fail=1; fi; done
recv=$(curl -s "http://127.0.0.1:$(port lrt-am-$$ 9093)/api/v2/alerts" | python3 -c "import json,sys; print(' '.join(sorted(f\"{a['labels']['alertname']}/{a['labels']['severity']}\" for a in json.load(sys.stdin))))")
if [[ "$recv" == "JobsDeadIncreased/critical JobsQueueLagging/warning" ]]; then echo "PASS alertmanager received: $recv"; else echo "FAIL alertmanager received: '$recv'"; fail=1; fi
exit $fail
