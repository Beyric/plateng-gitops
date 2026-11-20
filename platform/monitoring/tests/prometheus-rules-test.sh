#!/usr/bin/env bash
# Unit-tests PrometheusRule alerts in platform/monitoring/alerts.yaml with the
# promtool of the Prometheus version running in the cluster. Needs Docker and a
# python3 with PyYAML. Run from the repo root:
#   bash platform/monitoring/tests/prometheus-rules-test.sh
set -euo pipefail

PROM_IMAGE="${PROM_IMAGE:-quay.io/prometheus/prometheus:v3.14.0}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A PrometheusRule's .spec is a plain Prometheus rules file.
python3 - "$WORK/rules.yaml" <<'PY'
import sys, yaml
doc = yaml.safe_load(open("platform/monitoring/alerts.yaml"))
yaml.safe_dump(doc["spec"], open(sys.argv[1], "w"), sort_keys=False)
PY

cat > "$WORK/test.yaml" <<'YAML'
rule_files: [rules.yaml]
evaluation_interval: 1m
tests:
  # KarpenterNodeStuckDraining
  - interval: 1m
    input_series:
      # stuck: tainted for 90 minutes
      - series: 'kube_node_spec_taint{node="stuck",key="karpenter.sh/disrupted",effect="NoSchedule"}'
        values: '1x90'
      # decoy: a normal drain, 20 minutes, then the node is gone
      - series: 'kube_node_spec_taint{node="normal",key="karpenter.sh/disrupted",effect="NoSchedule"}'
        values: '1x20'
      # decoy: a different taint held for hours
      - series: 'kube_node_spec_taint{node="other",key="node.kubernetes.io/unschedulable",effect="NoSchedule"}'
        values: '1x90'
    alert_rule_test:
      - eval_time: 50m
        alertname: KarpenterNodeStuckDraining
        exp_alerts: []
      - eval_time: 75m
        alertname: KarpenterNodeStuckDraining
        exp_alerts:
          - exp_labels: { severity: warning, node: stuck }
            exp_annotations:
              summary: "stuck has been draining for over 1 hour"
              description: "A pod Karpenter will not evict (karpenter.sh/do-not-disrupt) is holding the node. Delete that pod at a quiet moment (no build in its Sonar stage) so it reschedules and the node can go."
              runbook_url: https://github.com/Beyric/plateng-infrastructure-tools/blob/main/projects/weysure/docs/runbooks/ALERTS.md#karpenternodestuckdraining

  # WeysureDbBackupMissing: last success at t=0 and none since -> quiet to 26 h, fires after 26 h + the 30 min "for"
  - interval: 1m
    input_series:
      - series: 'kube_cronjob_status_last_successful_time{namespace="weysure-prod",cronjob="weysure-db-backup"}'
        values: '0x1800'
    alert_rule_test:
      - eval_time: 20h
        alertname: WeysureDbBackupMissing
        exp_alerts: []
      - eval_time: 26h
        alertname: WeysureDbBackupMissing
        exp_alerts: []
      - eval_time: 28h
        alertname: WeysureDbBackupMissing
        exp_alerts:
          - exp_labels: { severity: warning, namespace: weysure-prod, cronjob: weysure-db-backup }
            exp_annotations:
              summary: "No successful off-AWS database backup in the last 26 hours"
              description: "The nightly CronJob weysure-prod/weysure-db-backup (02:30 UTC, pg_dump -> age -> Google Drive) has not succeeded. The newest copy outside AWS is more than a day old. RDS's own snapshots are unaffected."
              runbook_url: https://github.com/Beyric/plateng-infrastructure-tools/blob/main/projects/weysure/docs/runbooks/ALERTS.md#weysuredbbackupmissing
  # WeysureDbBackupMissing: last success at 24 h, checked at 40 h (16 h ago) -> quiet
  - interval: 1m
    input_series:
      - series: 'kube_cronjob_status_last_successful_time{namespace="weysure-prod",cronjob="weysure-db-backup"}'
        values: '86400x2400'
    alert_rule_test:
      - eval_time: 40h
        alertname: WeysureDbBackupMissing
        exp_alerts: []
  # WeysureDbBackupMissing: never succeeded. Created at t=0: quiet while the first night is still ahead, fires after 26 h
  - interval: 1m
    input_series:
      - series: 'kube_cronjob_created{namespace="weysure-prod",cronjob="weysure-db-backup"}'
        values: '0x1800'
    alert_rule_test:
      - eval_time: 10h
        alertname: WeysureDbBackupMissing
        exp_alerts: []
      - eval_time: 28h
        alertname: WeysureDbBackupMissing
        exp_alerts:
          - exp_labels: { severity: warning, namespace: weysure-prod, cronjob: weysure-db-backup }
            exp_annotations:
              summary: "No successful off-AWS database backup in the last 26 hours"
              description: "The nightly CronJob weysure-prod/weysure-db-backup (02:30 UTC, pg_dump -> age -> Google Drive) has not succeeded. The newest copy outside AWS is more than a day old. RDS's own snapshots are unaffected."
              runbook_url: https://github.com/Beyric/plateng-infrastructure-tools/blob/main/projects/weysure/docs/runbooks/ALERTS.md#weysuredbbackupmissing
  # WeysureDbBackupMissing: the CronJob does not exist at all -> nothing to alert on (no false page)
  - interval: 1m
    input_series:
      - series: 'up{job="unrelated"}'
        values: '1x1800'
    alert_rule_test:
      - eval_time: 30h
        alertname: WeysureDbBackupMissing
        exp_alerts: []
YAML

docker run --rm -v "$WORK:/w" -w /w --entrypoint promtool "$PROM_IMAGE" check rules rules.yaml
docker run --rm -v "$WORK:/w" -w /w --entrypoint promtool "$PROM_IMAGE" test rules test.yaml
echo "prometheus-rules-test OK"
