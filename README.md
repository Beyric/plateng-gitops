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
