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
# api-worker ships disabled until the image has app.worker; render it switched on too.
helm template weysure-api charts/beyric-app -n weysure-prod -f $P/apps/api/values.yaml -f $P/images.yaml --set components.api-worker.enabled=true > /tmp/beyric-app-api-worker.yaml
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
check(c['securityContext']['readOnlyRootFilesystem'] and pod['spec']['securityContext']['runAsNonRoot'] and c['securityContext']['runAsUser']==1000, 'api non-root read-only, container runAsUser set')
check(job['spec']['template']['spec']['containers'][0]['securityContext']['runAsUser']==1000, 'migration container runAsUser set (injector run-as-same-user)') if False else None
check(c['readinessProbe']['httpGet']['path']=='/api/v1/health' and c['startupProbe']['failureThreshold']==30, 'api probes')
check({'configMapRef': {'name': 'api-config'}} in c['envFrom'] and {'secretRef': {'name': 'weysure-app-config'}} in c['envFrom'], 'api envFrom configmap + secret')
cm=one(api,'ConfigMap','api-config')['data']; check(cm['RUN_MIGRATIONS']=='false' and cm['WALLET_RECONCILIATION_SCHEDULER_ENABLED']=='false', 'api config: no migrations, no scheduler')
sch=one(api,'ConfigMap','api-scheduler-config')['data']; check(sch['WALLET_RECONCILIATION_SCHEDULER_ENABLED']=='true' and sch['REDIS_URL']==cm['REDIS_URL'], 'scheduler config inherits common env, enables scheduler')
kyc=['TERMII_BASE_URL','TERMII_SENDER_ID','TERMII_OTP_CHANNEL','TERMII_OTP_TEMPLATE','OTP_EXPIRE_MINUTES','OTP_RESEND_COOLDOWN_SECONDS','OTP_RESEND_DAILY_CAP','DOJAH_ENVIRONMENT','DOJAH_BASE_URL','DOJAH_APP_ID','DOJAH_PUBLIC_KEY','DOJAH_BVN_WIDGET_ID','DOJAH_NIN_WIDGET_ID','DOJAH_FACE_MATCH_THRESHOLD']
for name,data in (('api',cm),('api-scheduler',sch)):
    check(all(data.get(k) for k in kyc), f'{name}: all 14 KYC config values present and non-empty')
    check(data.get('TERMII_SENDER_ID')=='N-Alert', f'{name}: Termii sender ID in its registered case')
    check('{code}' in data.get('TERMII_OTP_TEMPLATE','') and data.get('OTP_EXPIRE_MINUTES')=='10', f'{name}: OTP template keeps {{code}} and the approved 10 minutes')
    check(not any(k in data for k in ('TERMII_API_KEY','DOJAH_API_KEY','DOJAH_WEBHOOK_SECRET','KYC_FINGERPRINT_KEY')), f'{name}: no secret in the ConfigMap')
    env=data.get('ENVIRONMENT','').strip().lower()
    check(env and env not in ('development','dev','test','testing','local'), f'{name}: ENVIRONMENT set and not one that enables fake providers')
    check(env not in ('production','prod') or (data.get('DOJAH_ENVIRONMENT')=='production' and 'sandbox' not in data.get('DOJAH_BASE_URL','')), f'{name}: production ENVIRONMENT never with Dojah sandbox (the API refuses to boot)')
    check((data.get('DOJAH_ENVIRONMENT')=='sandbox')==('sandbox' in data.get('DOJAH_BASE_URL','')) and (data.get('DOJAH_ENVIRONMENT')=='sandbox')==data.get('DOJAH_PUBLIC_KEY','').startswith('test_'), f'{name}: Dojah environment, host and public key agree')
check(one(api,'Deployment','api-scheduler')['spec']['replicas']==1, 'scheduler single replica')
check(not [d for d in api if d['kind']=='Service' and d['metadata']['name']=='api-scheduler'], 'scheduler has no Service')
job=one(api,'Job','weysure-api-db-migrate'); ja=job['spec']['template']['metadata']['annotations']
check(job['metadata']['annotations']['argocd.argoproj.io/hook']=='PreSync' and 'HookSucceeded' in job['metadata']['annotations']['argocd.argoproj.io/hook-delete-policy'], 'migration job is a PreSync hook')
check(ja.get('vault.hashicorp.com/agent-pre-populate-only')=='true' and ja.get('vault.hashicorp.com/role')=='weysure-migrate', 'migration uses init-only agent with migrate role')
sa=one(api,'ServiceAccount','db-migrate')['metadata']['annotations']; check(sa.get('argocd.argoproj.io/hook')=='PreSync' and sa.get('argocd.argoproj.io/sync-wave')=='-1', 'migration SA is a PreSync hook before the Job')
jc=job['spec']['template']['spec']['containers'][0]; jenv={e['name']:e.get('value') for e in jc['env']}; check(list(jenv)==['VAULT_ENV_FILE'], 'migration job env is VAULT_ENV_FILE only')
check('envFrom' not in jc, 'migration job mounts no application secret (no SECRET_KEY)')
for n in ('api','api-scheduler'):
    pc=one(api,'Deployment',n)['spec']['template']['spec']; mounts=sorted(m['mountPath'] for m in pc['containers'][0].get('volumeMounts',[]) if not m['mountPath'].startswith('/vault'))
    check(mounts==['/tmp'], f'{n}: /tmp is the only writable path, got {mounts}')
check(job['spec']['template']['spec']['containers'][0]['securityContext']['runAsUser']==1000, 'migration container runAsUser set (injector run-as-same-user)')
check(job['spec']['backoffLimit']==0 and job['spec']['template']['spec']['serviceAccountName']=='db-migrate', 'migration job SA + no retries')
es=one(api,'ExternalSecret','weysure-app-config'); check(es['metadata']['annotations'].get('argocd.argoproj.io/hook')=='PreSync' and es['metadata']['annotations'].get('argocd.argoproj.io/sync-wave')=='-2', 'ExternalSecret is a PreSync hook before the migration Job'); check(es['spec']['dataFrom'][0]['extract']['key']=='weysure/prod' and es['spec']['secretStoreRef']['name']=='vault', 'ExternalSecret from weysure/prod')
ing=one(api,'Ingress','api'); check(ing['spec']['rules'][0]['host']=='weysure-api.beyrictech.com' and ing['metadata']['annotations']['cert-manager.io/cluster-issuer']=='letsencrypt-prod', 'api ingress + cert')
check(one(api,'PodDisruptionBudget','api')['spec']['minAvailable']==1 and one(api,'HorizontalPodAutoscaler','api')['spec']['maxReplicas']==4, 'api PDB + HPA')
check(one(api,'ServiceAccount','api')['automountServiceAccountToken'] is True, 'api SA token mounted for vault auth')
# api-worker (queue worker, no port)
check(not [d for d in api if d['metadata']['name'].startswith('api-worker')], 'api-worker renders nothing while disabled')
wk=load('/tmp/beyric-app-api-worker.yaml'); wdep=one(wk,'Deployment','api-worker'); wps=wdep['spec']['template']['spec']; wcc=wps['containers'][0]; wa=wdep['spec']['template']['metadata']['annotations']
check(wdep['spec']['replicas']==1 and wps['serviceAccountName']=='api-worker' and one(wk,'ServiceAccount','api-worker')['automountServiceAccountToken'] is True, 'api-worker: 1 replica, own SA with token for Vault')
check(wa.get('vault.hashicorp.com/role')=='weysure-api' and wa.get('vault.hashicorp.com/agent-pre-populate')=='false' and wps.get('shareProcessNamespace') is True, 'api-worker: same Vault DB role as api, sidecar, shared PID namespace')
check("[a]pp.worker" in wa.get('vault.hashicorp.com/agent-inject-command-env','') and 'gunicorn' not in wa.get('vault.hashicorp.com/agent-inject-command-env',''), 'api-worker: credential rotation signals the worker, not gunicorn')
check("[b]in/gunicorn" in one(wk,'Deployment','api')['spec']['template']['metadata']['annotations']['vault.hashicorp.com/agent-inject-command-env'], 'api keeps the gunicorn restart command')
check('ports' not in wcc and 'readinessProbe' not in wcc and 'lifecycle' not in wcc, 'api-worker: no port, no readiness, no preStop sleep')
check('/tmp/worker-heartbeat' in str(wcc['livenessProbe']['exec']) and '-lt 45' in str(wcc['livenessProbe']['exec']) and 'exec' in wcc['startupProbe'], 'api-worker: heartbeat startup + liveness probes (45s)')
check(wps['terminationGracePeriodSeconds']==60, 'api-worker: 60s to finish the running job')
check('exec python -m app.worker' in wcc['command'][-1] and 'VAULT_ENV_FILE' in wcc['command'][-1], 'api-worker: wrapper loads the Vault credential then execs the worker')
check(wcc['image']==one(wk,'Deployment','api')['spec']['template']['spec']['containers'][0]['image'], 'api-worker: same image as api')
check({'configMapRef': {'name': 'api-worker-config'}} in wcc['envFrom'] and {'secretRef': {'name': 'weysure-app-config'}} in wcc['envFrom'] and one(wk,'ConfigMap','api-worker-config')['data']['ENVIRONMENT']==cm['ENVIRONMENT'], 'api-worker: same config and secret as api')
check(not [d for d in wk if d['kind'] in ('Service','Ingress','PodDisruptionBudget','HorizontalPodAutoscaler') and d['metadata']['name']=='api-worker'], 'api-worker: no Service, Ingress, PDB or HPA')
# web
wd=one(web,'Deployment','web'); wp=wd['spec']['template']; wc=wp['spec']['containers'][0]
check(wc['image'].endswith(':'+images['web']['tag']), 'web image tag from images.yaml')
check('vault.hashicorp.com/agent-inject' not in str(wp['metadata'].get('annotations',{})), 'web has no vault agent')
check(wp['spec']['securityContext']['runAsUser']==1001 and wc['securityContext']['runAsUser']==1001 and wc['securityContext']['readOnlyRootFilesystem'], 'web uid 1001 at pod and container level')
check(one(web,'Ingress','web')['spec']['rules'][0]['host']=='weysure.beyrictech.com', 'web ingress host')
check(not [d for d in web if d['kind'] in ('Job','ExternalSecret')], 'web has no migration/externalsecret')
check(one(web,'ServiceAccount','web')['automountServiceAccountToken'] is False, 'web SA token not mounted')
for d in api+web:
    check(d['metadata'].get('namespace')=='weysure-prod', f"{d['kind']}/{d['metadata']['name']} in weysure-prod")
if fails: print("FAIL:\n  "+"\n  ".join(fails)); sys.exit(1)
print(f"render-test OK: {len(api)} api objects, {len(web)} web objects, all assertions passed")
PY
