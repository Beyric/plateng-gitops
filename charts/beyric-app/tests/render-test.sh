#!/usr/bin/env bash
# Renders charts/beyric-app with the real prod values (as Argo CD does) and
# asserts the properties the Phase 7 spec promises. Run from the repo root.
set -euo pipefail
cd "$(dirname "$0")/../../.."
P=projects/weysure/environments/prod
helm lint charts/beyric-app -f $P/apps/api/values.yaml -f $P/images.yaml --quiet
helm lint charts/beyric-app -f $P/apps/web/values.yaml -f $P/images.yaml --quiet
helm template weysure-api charts/beyric-app -n weysure-prod -f $P/apps/api/values.yaml -f $P/images.yaml > /tmp/beyric-app-api.yaml
helm template weysure-web charts/beyric-app -n weysure-prod -f $P/apps/web/values.yaml -f $P/images.yaml > /tmp/beyric-app-web.yaml
python3 - <<'PY'
import yaml, sys
def load(p): return [d for d in yaml.safe_load_all(open(p)) if d]
api, web = load('/tmp/beyric-app-api.yaml'), load('/tmp/beyric-app-web.yaml')
def one(docs, kind, name):
    m=[d for d in docs if d['kind']==kind and d['metadata']['name']==name]; assert len(m)==1, f"{kind}/{name}: {len(m)}"; return m[0]
fails=[]
def check(cond, msg):
    if not cond: fails.append(msg)
images = yaml.safe_load(open('projects/weysure/environments/prod/images.yaml'))
dep=one(api,'Deployment','api'); pod=dep['spec']['template']; c=pod['spec']['containers'][0]
check(c['image'].endswith(':'+images['api']['tag']), 'api image tag comes from images.yaml')
check(dep['spec']['replicas']==2 and dep['spec']['strategy']['rollingUpdate']['maxUnavailable']==0, 'api 2 replicas, maxUnavailable 0')
a=pod['metadata']['annotations']
check(a.get('vault.hashicorp.com/agent-inject')=='true' and a.get('vault.hashicorp.com/role')=='weysure-api', 'api pod has vault agent annotations')
check('agent-pre-populate-only' not in str(a) and a.get('vault.hashicorp.com/agent-pre-populate')=='false', 'api uses sidecar only (single lease)')
check('sslmode=require' in a['vault.hashicorp.com/agent-inject-template-env'] and '{{ .Data.password }}' in a['vault.hashicorp.com/agent-inject-template-env'], 'DATABASE_URL template renders creds with sslmode')
check(pod['spec'].get('shareProcessNamespace') is True, 'api shares PID namespace for restart-on-rotate')
check(c['securityContext']['readOnlyRootFilesystem'] and pod['spec']['securityContext']['runAsNonRoot'], 'api non-root read-only')
check(c['readinessProbe']['httpGet']['path']=='/api/v1/health' and c['startupProbe']['failureThreshold']==30, 'api probes')
check({'configMapRef': {'name': 'api-config'}} in c['envFrom'] and {'secretRef': {'name': 'weysure-app-config'}} in c['envFrom'], 'api envFrom configmap + secret')
cm=one(api,'ConfigMap','api-config')['data']; check(cm['RUN_MIGRATIONS']=='false' and cm['WALLET_RECONCILIATION_SCHEDULER_ENABLED']=='false', 'api config: no migrations, no scheduler')
sch=one(api,'ConfigMap','api-scheduler-config')['data']; check(sch['WALLET_RECONCILIATION_SCHEDULER_ENABLED']=='true' and sch['REDIS_URL']==cm['REDIS_URL'], 'scheduler config inherits common env, enables scheduler')
check(one(api,'Deployment','api-scheduler')['spec']['replicas']==1, 'scheduler single replica')
check(not [d for d in api if d['kind']=='Service' and d['metadata']['name']=='api-scheduler'], 'scheduler has no Service')
job=one(api,'Job','weysure-api-db-migrate'); ja=job['spec']['template']['metadata']['annotations']
check(job['metadata']['annotations']['argocd.argoproj.io/hook']=='PreSync' and 'HookSucceeded' in job['metadata']['annotations']['argocd.argoproj.io/hook-delete-policy'], 'migration job is a PreSync hook')
check(ja.get('vault.hashicorp.com/agent-pre-populate-only')=='true' and ja.get('vault.hashicorp.com/role')=='weysure-migrate', 'migration uses init-only agent with migrate role')
sa=one(api,'ServiceAccount','db-migrate')['metadata']['annotations']; check(sa.get('argocd.argoproj.io/hook')=='PreSync' and sa.get('argocd.argoproj.io/sync-wave')=='-1', 'migration SA is a PreSync hook before the Job')
jenv={e['name']:e.get('value') for e in job['spec']['template']['spec']['containers'][0]['env']}; check(jenv.get('SERVER_HOST','').startswith('https://') and 'VAULT_ENV_FILE' in jenv, 'migration job has SERVER_HOST + VAULT_ENV_FILE env')
check(job['spec']['backoffLimit']==0 and job['spec']['template']['spec']['serviceAccountName']=='db-migrate', 'migration job SA + no retries')
es=one(api,'ExternalSecret','weysure-app-config'); check(es['metadata']['annotations'].get('argocd.argoproj.io/hook')=='PreSync' and es['metadata']['annotations'].get('argocd.argoproj.io/sync-wave')=='-2', 'ExternalSecret is a PreSync hook before the migration Job'); check(es['spec']['dataFrom'][0]['extract']['key']=='weysure/prod' and es['spec']['secretStoreRef']['name']=='vault', 'ExternalSecret from weysure/prod')
ing=one(api,'Ingress','api'); check(ing['spec']['rules'][0]['host']=='weysure-api.beyrictech.com' and ing['metadata']['annotations']['cert-manager.io/cluster-issuer']=='letsencrypt-prod', 'api ingress + cert')
check(one(api,'PodDisruptionBudget','api')['spec']['minAvailable']==1 and one(api,'HorizontalPodAutoscaler','api')['spec']['maxReplicas']==4, 'api PDB + HPA')
check(one(api,'ServiceAccount','api')['automountServiceAccountToken'] is True, 'api SA token mounted for vault auth')
# web
wd=one(web,'Deployment','web'); wp=wd['spec']['template']; wc=wp['spec']['containers'][0]
check(wc['image'].endswith(':'+images['web']['tag']), 'web image tag from images.yaml')
check('vault.hashicorp.com/agent-inject' not in str(wp['metadata'].get('annotations',{})), 'web has no vault agent')
check(wp['spec']['securityContext']['runAsUser']==1001 and wc['securityContext']['readOnlyRootFilesystem'], 'web uid 1001 read-only')
check(one(web,'Ingress','web')['spec']['rules'][0]['host']=='weysure.beyrictech.com', 'web ingress host')
check(not [d for d in web if d['kind'] in ('Job','ExternalSecret')], 'web has no migration/externalsecret')
check(one(web,'ServiceAccount','web')['automountServiceAccountToken'] is False, 'web SA token not mounted')
for d in api+web:
    check(d['metadata'].get('namespace')=='weysure-prod', f"{d['kind']}/{d['metadata']['name']} in weysure-prod")
if fails: print("FAIL:\n  "+"\n  ".join(fails)); sys.exit(1)
print(f"render-test OK: {len(api)} api objects, {len(web)} web objects, all assertions passed")
PY
