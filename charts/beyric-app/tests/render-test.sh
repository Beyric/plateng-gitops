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
# api-worker is on in prod (2026-10-05); render it switched off too, as the chart default path.
helm template weysure-api charts/beyric-app -n weysure-prod -f $P/apps/api/values.yaml -f $P/images.yaml --set components.api-worker.enabled=false > /tmp/beyric-app-api-worker-off.yaml
# Rollback stops the worker in git with replicas: 0; it must render 0, not the default.
helm template weysure-api charts/beyric-app -n weysure-prod -f $P/apps/api/values.yaml -f $P/images.yaml --set components.api-worker.replicas=0 > /tmp/beyric-app-api-worker-zero.yaml
# STAGE (weysure-stage): same chart, stage values. Asserted below against prod's render.
S=projects/weysure/environments/stage
helm lint charts/beyric-app -f $S/apps/api/values.yaml -f $S/images.yaml --quiet
helm lint charts/beyric-app -f $S/apps/web/values.yaml -f $S/images.yaml --quiet
helm template weysure-api charts/beyric-app -n weysure-stage -f $S/apps/api/values.yaml -f $S/images.yaml > /tmp/beyric-app-stage-api.yaml
helm template weysure-web charts/beyric-app -n weysure-stage -f $S/apps/web/values.yaml -f $S/images.yaml > /tmp/beyric-app-stage-web.yaml
python3 - <<'PY'
import yaml, sys, json
def load(p): return [d for d in yaml.safe_load_all(open(p)) if d]
api, web = load('/tmp/beyric-app-api.yaml'), load('/tmp/beyric-app-web.yaml')
def one(docs, kind, name):
    m=[d for d in docs if d['kind']==kind and d['metadata']['name']==name]; assert len(m)==1, f"{kind}/{name}: {len(m)}"; return m[0]
fails=[]
def ja_sidecar_ok(docs):
    ds=[d for d in docs if d['kind']=='Deployment' and d['spec']['template']['metadata'].get('annotations',{}).get('vault.hashicorp.com/agent-inject')=='true']
    return len(ds)==2 and all(d['spec']['template']['metadata']['annotations'].get('vault.hashicorp.com/agent-limits-cpu')=='100m' for d in ds)
def check(cond, msg):
    if not cond: fails.append(msg)
images = yaml.safe_load(open('projects/weysure/environments/prod/images.yaml'))
dep=one(api,'Deployment','api'); pod=dep['spec']['template']; c=pod['spec']['containers'][0]
check(c['image'].endswith(':'+images['api']['tag']), 'api image tag comes from images.yaml')
# Mirrors the API's boot guard (Weysure-API app/core/config.py, _dva_settings_are_coherent): a pod that
# fails it never starts, so catch the ordering mistake here, not in the rollout.
for name in ('api', 'api-worker'):
    e = one(api, 'ConfigMap', name + '-config')['data']
    if e.get('DVA_CREATE_ENABLED') == 'true':
        check(e.get('ORIGIN_RULES_ENFORCED') == 'true', f'{name}: DVA_CREATE_ENABLED needs ORIGIN_RULES_ENFORCED=true')
        check('enforce' in (e.get('RISK_HOLDS_MODE'), e.get('CHARGEBACKS_MODE')), f'{name}: DVA_CREATE_ENABLED needs RISK_HOLDS_MODE or CHARGEBACKS_MODE = enforce')
    if e.get('DVA_REFUND_ENABLED') == 'true':
        check(e.get('REFUND_TO_SOURCE_ENABLED') == 'true', f'{name}: DVA_REFUND_ENABLED needs REFUND_TO_SOURCE_ENABLED=true')
    # Mirrors Weysure-API app/core/boot_guard.py _session_enforcement_problems (L10).
    if e.get('MFA_ADMIN_REQUIRED') == 'true' or e.get('MFA_STEP_UP_ENFORCED') == 'enforce':
        check(e.get('SESSION_SID_ENFORCED') == 'true', f'{name}: MFA_ADMIN_REQUIRED / step-up enforce needs SESSION_SID_ENFORCED=true')
    # Weysure-API app/core/auth_cookies.py: __Host- needs Secure, so COOKIE_HOST_PREFIX is silently ignored
    # while REFRESH_COOKIE_SECURE is false. Unset means the API default (true).
    if e.get('COOKIE_HOST_PREFIX') == 'true':
        check(e.get('REFRESH_COOKIE_SECURE', 'true') != 'false', f'{name}: COOKIE_HOST_PREFIX needs REFRESH_COOKIE_SECURE=true (else the flag does nothing)')
    # Mirrors Weysure-API app/core/config.py _chargeback_settings_are_coherent: enforce needs origin rules.
    if e.get('CHARGEBACKS_MODE') == 'enforce':
        check(e.get('ORIGIN_RULES_ENFORCED') == 'true', f'{name}: CHARGEBACKS_MODE=enforce needs ORIGIN_RULES_ENFORCED=true (the API refuses to boot)')
    # Mirrors app/core/boot_guard.py _cookie_mode_problems: the access cookie must be Secure and CORS https-only.
    if e.get('ACCESS_COOKIE_MODE', 'off') != 'off':
        check(e.get('REFRESH_COOKIE_SECURE', 'true') != 'false', f'{name}: ACCESS_COOKIE_MODE needs REFRESH_COOKIE_SECURE=true')
        check(all(o.startswith('https://') for o in json.loads(e.get('BACKEND_CORS_ORIGINS', '[]'))), f'{name}: ACCESS_COOKIE_MODE needs https-only BACKEND_CORS_ORIGINS')
    # app/core/config.py: self-serve MFA recovery needs MFA on.
    if e.get('MFA_RECOVERY_SELF_SERVE') == 'true':
        check(e.get('MFA_ENABLED') == 'true', f'{name}: MFA_RECOVERY_SELF_SERVE needs MFA_ENABLED=true')
    # 2026-11-17 (Adebayo: switch everything on): no feature stays dark. Both pod types carry every switch.
    # Not asserted on purpose: MFA_RECOVERY_SELF_SERVE (needs a Dojah selfie widget id in the web image),
    # IDENTITY_RELEASE_ENABLED and RATINGS_PUBLIC_READ (policy choices, not dark features).
    on = ('CHARGEBACK_AUTO_RESPOND_ENABLED', 'SOURCE_REFUND_RETRY_ENABLED', 'DEAL_INVITES_ENABLED', 'BUSINESS_PAYMENT_EXPIRY_ENABLED',
          'BUSINESS_AUTO_RELEASE_ENABLED', 'BUSINESS_HOLD_EXPIRY_ENABLED', 'BUSINESS_PAYOUT_RETRY_ENABLED', 'REFRESH_REPLAY_REISSUE',
          'NEW_DEVICE_ALERTS_ENABLED')
    check(all(e.get(k) == 'true' for k in on), f'{name}: every switched-on feature flag is "true": {[k for k in on if e.get(k) != "true"]}')
    check(e.get('CHARGEBACKS_MODE') == 'enforce' and e.get('ACCESS_COOKIE_MODE') == 'dual', f'{name}: chargebacks enforce, access cookie dual (bearer and cookie both work)')
check(dep['spec']['replicas']==2 and dep['spec']['strategy']['rollingUpdate']['maxUnavailable']==0, 'api 2 replicas, maxUnavailable 0')
a=pod['metadata']['annotations']
check(a.get('vault.hashicorp.com/agent-inject')=='true' and a.get('vault.hashicorp.com/role')=='weysure-api', 'api pod has vault agent annotations')
check('agent-pre-populate-only' not in str(a) and a.get('vault.hashicorp.com/agent-pre-populate')=='false', 'api uses sidecar only (single lease)')
check('sslmode=require' in a['vault.hashicorp.com/agent-inject-template-env'] and '{{ .Data.password }}' in a['vault.hashicorp.com/agent-inject-template-env'], 'DATABASE_URL template renders creds with sslmode')
check(a.get('vault.hashicorp.com/agent-limits-cpu')=='100m' and a.get('vault.hashicorp.com/agent-requests-cpu')=='20m', 'api vault agent has an explicit CPU limit (else the injector applies 500m)')
check(ja_sidecar_ok(api), 'every vault-agent sidecar pod (api, worker) sets agent-limits-cpu')
check(pod['spec'].get('shareProcessNamespace') is True, 'api shares PID namespace for restart-on-rotate')
check(c['securityContext']['readOnlyRootFilesystem'] and pod['spec']['securityContext']['runAsNonRoot'] and c['securityContext']['runAsUser']==1000, 'api non-root read-only, container runAsUser set')
check(job['spec']['template']['spec']['containers'][0]['securityContext']['runAsUser']==1000, 'migration container runAsUser set (injector run-as-same-user)') if False else None
check(c['readinessProbe']['httpGet']['path']=='/api/v1/health' and c['startupProbe']['failureThreshold']==30, 'api probes')
check({'configMapRef': {'name': 'api-config'}} in c['envFrom'] and {'secretRef': {'name': 'weysure-app-config'}} in c['envFrom'], 'api envFrom configmap + secret')
cm=one(api,'ConfigMap','api-config')['data']; check(cm['RUN_MIGRATIONS']=='false' and cm['WALLET_RECONCILIATION_SCHEDULER_ENABLED']=='false', 'api config: no migrations, no scheduler')
wk=one(api,'ConfigMap','api-worker-config')['data']; check(wk['WALLET_RECONCILIATION_SCHEDULER_ENABLED']=='true' and wk['REDIS_URL']==cm['REDIS_URL'], 'worker config inherits common env, runs the reconciliation (Weysure-API #68)')
kyc=['TERMII_BASE_URL','TERMII_SENDER_ID','TERMII_OTP_CHANNEL','TERMII_OTP_TEMPLATE','OTP_EXPIRE_MINUTES','OTP_RESEND_COOLDOWN_SECONDS','OTP_RESEND_DAILY_CAP','DOJAH_ENVIRONMENT','DOJAH_BASE_URL','DOJAH_APP_ID','DOJAH_PUBLIC_KEY','DOJAH_BVN_WIDGET_ID','DOJAH_NIN_WIDGET_ID','DOJAH_FACE_MATCH_THRESHOLD']
for name,data in (('api',cm),('api-worker',wk)):
    check(all(data.get(k) for k in kyc), f'{name}: all 14 KYC config values present and non-empty')
    check(data.get('TERMII_SENDER_ID')=='OE Alert', f'{name}: Termii sender ID in its registered case')
    check('{code}' in data.get('TERMII_OTP_TEMPLATE','') and data.get('OTP_EXPIRE_MINUTES')=='10', f'{name}: OTP template keeps {{code}} and the approved 10 minutes')
    check(not any(k in data for k in ('TERMII_API_KEY','DOJAH_API_KEY','DOJAH_WEBHOOK_SECRET','KYC_FINGERPRINT_KEY')), f'{name}: no secret in the ConfigMap')
    env=data.get('ENVIRONMENT','').strip().lower()
    check(env and env not in ('development','dev','test','testing','local'), f'{name}: ENVIRONMENT set and not one that enables fake providers')
    check(env not in ('production','prod') or (data.get('DOJAH_ENVIRONMENT')=='production' and 'sandbox' not in data.get('DOJAH_BASE_URL','')), f'{name}: production ENVIRONMENT never with Dojah sandbox (the API refuses to boot)')
    check((data.get('DOJAH_ENVIRONMENT')=='sandbox')==('sandbox' in data.get('DOJAH_BASE_URL','')) and (data.get('DOJAH_ENVIRONMENT')=='sandbox')==data.get('DOJAH_PUBLIC_KEY','').startswith('test_'), f'{name}: Dojah environment, host and public key agree')
for n in ('api-config','api-worker-config'):
    d=one(api,'ConfigMap',n)['data']
    check(d.get('ORIGIN_RULES_ENFORCED')=='true' and d.get('RISK_HOLDS_MODE')=='enforce' and d.get('RISK_SIGNALS_CAPTURE_ENABLED')=='true' and d.get('TRUSTED_PROXY_CIDRS')=='10.0.0.0/16', f'{n}: origin rules on, risk holds enforce, capture on, trusted proxy = VPC')
    check(d.get('WS_ALLOW_URL_TOKEN')=='false', f'{n}: WebSocket token never accepted in the URL')
    check(not (d.get('RISK_HOLDS_MODE')=='enforce' and d.get('ORIGIN_RULES_ENFORCED')!='true'), f'{n}: enforce never without origin rules (the API refuses to boot)')
check(not [d for d in api if d['metadata']['name'].startswith('api-scheduler')], 'api-scheduler removed (2026-10-26): no Deployment, ConfigMap, ServiceAccount or Service')
job=one(api,'Job','weysure-api-db-migrate'); ja=job['spec']['template']['metadata']['annotations']
check(job['metadata']['annotations']['argocd.argoproj.io/hook']=='PreSync' and 'HookSucceeded' in job['metadata']['annotations']['argocd.argoproj.io/hook-delete-policy'], 'migration job is a PreSync hook')
check(ja.get('vault.hashicorp.com/agent-pre-populate-only')=='true' and ja.get('vault.hashicorp.com/role')=='weysure-migrate', 'migration uses init-only agent with migrate role')
sa=one(api,'ServiceAccount','db-migrate')['metadata']['annotations']; check(sa.get('argocd.argoproj.io/hook')=='PreSync' and sa.get('argocd.argoproj.io/sync-wave')=='-1', 'migration SA is a PreSync hook before the Job')
jc=job['spec']['template']['spec']['containers'][0]; jenv={e['name']:e.get('value') for e in jc['env']}; check(list(jenv)==['VAULT_ENV_FILE'], 'migration job env is VAULT_ENV_FILE only')
check('envFrom' not in jc, 'migration job mounts no application secret (no SECRET_KEY)')
for n in ('api',):
    pc=one(api,'Deployment',n)['spec']['template']['spec']; mounts=sorted(m['mountPath'] for m in pc['containers'][0].get('volumeMounts',[]) if not m['mountPath'].startswith('/vault'))
    check(mounts==['/tmp'], f'{n}: /tmp is the only writable path, got {mounts}')
check(job['spec']['template']['spec']['containers'][0]['securityContext']['runAsUser']==1000, 'migration container runAsUser set (injector run-as-same-user)')
for docs,n,want in ((api,'api','DoNotSchedule'),(web,'web','DoNotSchedule'),(api,'api-worker','ScheduleAnyway')):
    t=one(docs,'Deployment',n)['spec']['template']['spec']['topologySpreadConstraints'][0]
    check(t['whenUnsatisfiable']==want and t['topologyKey']=='kubernetes.io/hostname' and t['matchLabelKeys']==['pod-template-hash'] and t['nodeTaintsPolicy']=='Honor', f'{n}: hostname spread {want}, per ReplicaSet, taints honoured')
    md = 2 if want=='DoNotSchedule' else None
    check(t.get('minDomains')==md, f'{n}: minDomains {md}')
check(job['spec']['backoffLimit']==0 and job['spec']['template']['spec']['serviceAccountName']=='db-migrate', 'migration job SA + no retries')
es=one(api,'ExternalSecret','weysure-app-config'); check(es['metadata']['annotations'].get('argocd.argoproj.io/hook')=='PreSync' and es['metadata']['annotations'].get('argocd.argoproj.io/sync-wave')=='-2', 'ExternalSecret is a PreSync hook before the migration Job'); check(es['spec']['dataFrom'][0]['extract']['key']=='weysure/prod' and es['spec']['secretStoreRef']['name']=='vault', 'ExternalSecret from weysure/prod')
ing=one(api,'Ingress','api'); check(ing['spec']['rules'][0]['host']=='api.weysure.com' and len(ing['spec']['rules'])==1 and ing['spec']['tls']==[{'secretName':'api-extra-tls','hosts':['api.weysure.com']}] and ing['metadata']['annotations']['cert-manager.io/cluster-issuer']=='letsencrypt-prod', 'api ingress: only api.weysure.com, certificate Secret api-extra-tls')
check(one(api,'PodDisruptionBudget','api')['spec']['minAvailable']==1 and one(api,'HorizontalPodAutoscaler','api')['spec']['maxReplicas']==4, 'api PDB + HPA')
check(one(api,'ServiceAccount','api')['automountServiceAccountToken'] is True, 'api SA token mounted for vault auth')
# api-worker (queue worker, no port)
check(not [d for d in load('/tmp/beyric-app-api-worker-off.yaml') if d['metadata']['name'].startswith('api-worker')], 'api-worker renders nothing when disabled')
wk=api; wdep=one(wk,'Deployment','api-worker'); wps=wdep['spec']['template']['spec']; wcc=wps['containers'][0]; wa=wdep['spec']['template']['metadata']['annotations']
check(wdep['spec']['replicas']==1 and wps['serviceAccountName']=='api-worker' and one(wk,'ServiceAccount','api-worker')['automountServiceAccountToken'] is True, 'api-worker: 1 replica, own SA with token for Vault')
check(wa.get('vault.hashicorp.com/role')=='weysure-api' and wa.get('vault.hashicorp.com/agent-pre-populate')=='false' and wps.get('shareProcessNamespace') is True, 'api-worker: same Vault DB role as api, sidecar, shared PID namespace')
check("'^python -m app[.]worker'" in wa.get('vault.hashicorp.com/agent-inject-command-env','') and 'gunicorn' not in wa.get('vault.hashicorp.com/agent-inject-command-env',''), 'api-worker: credential rotation signals the worker (anchored, never the waiting wrapper), not gunicorn')
check("[b]in/gunicorn" in one(wk,'Deployment','api')['spec']['template']['metadata']['annotations']['vault.hashicorp.com/agent-inject-command-env'], 'api keeps the gunicorn restart command')
check('ports' not in wcc and 'readinessProbe' not in wcc and 'lifecycle' not in wcc, 'api-worker: no port, no readiness, no preStop sleep')
check('/tmp/worker-heartbeat' in str(wcc['livenessProbe']['exec']) and '-lt 45' in str(wcc['livenessProbe']['exec']) and 'exec' in wcc['startupProbe'], 'api-worker: heartbeat startup + liveness probes (45s)')
check(wps['terminationGracePeriodSeconds']==60, 'api-worker: 60s to finish the running job')
check(one(load('/tmp/beyric-app-api-worker-zero.yaml'),'Deployment','api-worker')['spec']['replicas']==0, 'replicas: 0 renders 0 (rollback stops the worker in git)')
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
# ---- STAGE: rehearses prod, and cannot move real money ----------------------------------------------------------------
sapi, sweb = load('/tmp/beyric-app-stage-api.yaml'), load('/tmp/beyric-app-stage-web.yaml')
simages = yaml.safe_load(open('projects/weysure/environments/stage/images.yaml'))
HOST_KEYS = {'ENVIRONMENT','SERVER_HOST','FRONTEND_URL','BACKEND_CORS_ORIGINS','WEBAUTHN_RP_ID','WEBAUTHN_ORIGINS'}
for n in ('api-config','api-worker-config'):
    p, q = one(api,'ConfigMap',n)['data'], one(sapi,'ConfigMap',n)['data']
    drift = sorted(k for k in set(p)|set(q) if p.get(k)!=q.get(k))
    check(set(drift)==HOST_KEYS, f'stage {n}: differs from prod only in {sorted(HOST_KEYS)} (every feature flag equals prod); differs in {drift}')
    check(q.get('ENVIRONMENT')=='staging' and q.get('DOJAH_ENVIRONMENT')=='sandbox' and 'sandbox' in q.get('DOJAH_BASE_URL',''), f'stage {n}: ENVIRONMENT staging, Dojah sandbox')
    check(all(('weysure.com' not in str(v)) or ('staging.weysure.com' in str(v)) or ('@weysure.com' in str(v)) for v in q.values()), f'stage {n}: no prod weysure.com URL in the config')
    check(q['WEBAUTHN_RP_ID']=='staging.weysure.com' and q['SERVER_HOST']=='https://api-staging.weysure.com' and q['FRONTEND_URL']=='https://staging.weysure.com', f'stage {n}: stage hosts')
ses=one(sapi,'ExternalSecret','weysure-app-config')
skeys=[d['remoteRef']['property'] for d in ses['spec'].get('data',[])]
check('dataFrom' not in ses['spec'] and skeys and len(skeys)==len(set(skeys)), 'stage ExternalSecret: explicit key list, not dataFrom.extract')
check(not [k for k in skeys if k.startswith('PAYSTACK_LIVE')] and all(d['remoteRef']['key']=='weysure/stage' for d in ses['spec']['data']), 'stage ExternalSecret: reads weysure/stage only and never a PAYSTACK_LIVE_* key')
check({'PAYSTACK_SECRET_KEY','PAYSTACK_TEST_SECRET_KEY','SECRET_KEY','MFA_ENCRYPTION_KEY','TERMII_API_KEY','DOJAH_API_KEY'} <= set(skeys), 'stage ExternalSecret: carries the keys the API refuses to boot without')
sdep=one(sapi,'Deployment','api'); sa_=sdep['spec']['template']['metadata']['annotations']
check(sdep['spec']['replicas']==1 and one(sapi,'Deployment','api-worker')['spec']['replicas']==1 and one(sweb,'Deployment','web')['spec']['replicas']==1, 'stage: 1 replica each of api, api-worker, web')
check(not [d for d in sapi+sweb if d['kind'] in ('HorizontalPodAutoscaler','PodDisruptionBudget')], 'stage: no HPA and no PDB (one replica)')
check(sa_.get('vault.hashicorp.com/role')=='weysure-stage-api' and 'database/creds/weysure-stage-app' in sa_.get('vault.hashicorp.com/agent-inject-secret-env','') and 'weysure-stage-postgres' in sa_['vault.hashicorp.com/agent-inject-template-env'], 'stage api: own Vault role, own DB credential path, stage database host')
sjob=one(sapi,'Job','weysure-api-db-migrate')['spec']['template']['metadata']['annotations']
check(sjob.get('vault.hashicorp.com/role')=='weysure-stage-migrate' and 'weysure-stage-postgres' in sjob['vault.hashicorp.com/agent-inject-template-env'], 'stage migration: own Vault role and stage database')
sing=one(sapi,'Ingress','api'); wing=one(sweb,'Ingress','web')
check([r['host'] for r in sing['spec']['rules']]==['api-staging.weysure.com'] and [r['host'] for r in wing['spec']['rules']]==['staging.weysure.com'], 'stage ingress hosts: api-staging.weysure.com, staging.weysure.com only')
check(all('weysure-stage-noindex@kubernetescrd' in i['metadata']['annotations'].get('traefik.ingress.kubernetes.io/router.middlewares','') for i in (sing,wing)), 'stage ingresses carry the noindex middleware')
check(simages['web']['tag']!=images['web']['tag'] and (simages['web']['tag'].endswith('-stage') or simages['web']['tag']=='not-built-yet'), 'stage web tag is never prod\'s web tag (it bakes the prod API URL): <sha>-stage or the placeholder')
check(simages['api']['tag'] and 'weysure-api' in one(sapi,'Deployment','api')['spec']['template']['spec']['containers'][0]['image'], 'stage api image from stage images.yaml')
for d in sapi+sweb:
    check(d['metadata'].get('namespace')=='weysure-stage', f"stage {d['kind']}/{d['metadata']['name']} in weysure-stage")
text=open('/tmp/beyric-app-stage-api.yaml').read()+open('/tmp/beyric-app-stage-web.yaml').read()
check('weysure-prod' not in text and 'weysure-postgres-v2' not in text and 'weysure/prod' not in text and 'weysure-app\n' not in text, 'stage render names nothing of prod (namespace, database host, Vault path)')
if fails: print("FAIL:\n  "+"\n  ".join(fails)); sys.exit(1)
print(f"render-test OK: {len(api)} api objects, {len(web)} web objects, all assertions passed")
PY
