# projects/weysure/manual/prod — hand-applied one-shot manifests

**Argo CD does not watch this directory.** The `weysure-prod` Application syncs
`projects/weysure/environments/prod` (recursive, automated, prune on); this path is outside it, so merging a file
here changes nothing in the cluster. A manifest here runs only when a human applies it.

| File | What | Run with |
|---|---|---|
| `db-reset-prod-v1-job.yaml` | wipes all Weysure data except the owner's admin account and the config tables | `scripts/db-reset-prod.sh dry`, then `real`, in `plateng-infrastructure-tools` (runbook: `projects/weysure/docs/runbooks/PROD_DATA_RESET.md` there) |

Why not `environments/prod/bootstrap/` like the other one-shot Jobs: a Job there is applied by Argo the moment
its PR merges. For a destructive Job, "merge = run" is not acceptable. Delete this directory once the reset is done.
