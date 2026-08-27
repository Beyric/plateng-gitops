# plateng-gitops

Kubernetes desired state. **Argo CD watches this repository and nothing else.**

## Rules

1. **Never run `kubectl apply` against a managed cluster.** Every change is a commit here.
   `kubectl` is a read-only instrument: `get`, `describe`, `logs`, `k9s`.
2. **This repository is production.** Branch protection and review are not optional.
3. **No secrets, ever.** Secrets live in Vault and reach pods through External Secrets
   Operator. A `kind: Secret` with literal `data` is a defect.
4. **Terraform does not belong here.** Cloud resources live in `plateng-infrastructure-tools`
   behind a human-gated `apply`. Whoever creates a resource must be the only thing that
   changes it — otherwise Terraform and Argo CD reconcile each other's changes forever.

## Layout

```text
bootstrap/                        Argo CD app-of-apps root
platform/                         Shared platform components
projects/
  weysure/
    apps/                         Application definitions
    environments/
      stage/                      Overlays and image tags — stage
      prod/                       Overlays and image tags — prod
```

## Who writes here

| Author | Writes | Why |
|---|---|---|
| Engineers | everything, via pull request | Desired state is reviewed like code |
| Jenkins (CI) | **only** an image tag under `environments/*/` | Its sole handoff; it holds no cluster credentials |

## Rollback

`git revert` the offending commit. Argo CD reconciles to the previous state. There is no
separate rollback tool.

## How the no-secrets rule is enforced

Rule 3 above is not honour-system. Two mechanical controls run on every commit,
and they cover different things:

| Control | Catches | Blind to |
|---|---|---|
| **`gitleaks`** (`.gitleaks.toml`) | Secret-*shaped* strings anywhere — API keys, tokens, private keys, high-entropy blobs | A correctly-formed Kubernetes `Secret` whose payload does not look like a known credential pattern |
| **`scripts/no-plaintext-secrets.py`** | Any YAML document with `kind: Secret` and a non-empty `data`/`stringData` — exactly, by parsing | Secret-shaped strings outside a Secret manifest |

Neither is sufficient alone. Install both before your first commit:

```bash
pre-commit install --install-hooks
```

### Why the second control is a parser and not a regex

A regex was tried first and removed. It failed in **both** directions, each confirmed
by canary:

- **False negative.** The rule used `kind:\s*Secret.{0,400}?^\s*(data|stringData):`.
  That `{0,400}` window is a stand-in for "the same YAML document". Eight ordinary
  annotations pushed `stringData` 897 characters past `kind:`, and a genuine plaintext
  credential scanned completely clean — `no leaks found`, exit 0.
- **False positive.** Matching `Secret` as a substring also matches `SecretStore`, so a
  legitimate namespaced `ExternalSecret` — the exact pattern this platform is built on —
  was rejected. The first correct manifest anyone wrote would have been blocked.

Both were the same mistake: using a regular expression to answer a structural question
about nested data. A parser knows where documents begin and end, and compares fields
rather than characters, so both defects disappear.

Worth internalising: a broken control is worse than an absent one, because it looks like
a control. The only reason either defect was found is that someone planted something the
scanner had to catch and checked that it screamed.

### What to write instead of a Secret

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: weysure-api
spec:
  secretStoreRef:
    name: vault
    kind: SecretStore
  target:
    name: weysure-api
  data:
    - secretKey: SECRET_KEY
      remoteRef:
        key: weysure/prod
        property: SECRET_KEY
```

Vault holds the value. External Secrets Operator creates the Kubernetes Secret in-cluster
at runtime. Reloader restarts the pods that consume it when it changes. Nothing sensitive
is ever in git.

Note the filename convention: these are conventionally named `<app>-secret.yaml`, which is
why `.gitignore` deliberately does **not** ignore `*-secret.yaml`. Doing so would silently
drop legitimate manifests — `git add -A` would skip them, `git status` would stay quiet,
and Argo CD would never reconcile them, with no error to explain the missing config.
