#!/usr/bin/env python3
"""Reject any Kubernetes Secret manifest carrying literal key material.

Why this exists as a parser rather than a regex
-----------------------------------------------
Argo CD reconciles this repository into a live cluster, so a plaintext Secret
committed here becomes a plaintext Secret running in production. Preventing that
is a structural question about a YAML document -- "is this document's `kind`
exactly Secret, and does it carry a non-empty data or stringData block?" -- and a
regular expression cannot answer a structural question about nested data.

Two real defects in the regex this replaces, both confirmed empirically:

  * A proximity window (`kind: Secret .{0,400}? data:`) stands in for "same
    document". Eight ordinary annotations push `stringData` 897 characters past
    `kind`, and a genuine plaintext credential scans clean.
  * Substring matching on `Secret` also matches `SecretStore`, so a legitimate
    namespaced ExternalSecret -- the exact pattern this platform is built on --
    is rejected.

A parser knows where documents begin and end, and compares fields rather than
characters. Both defects disappear because both were approximations of facts the
parser simply has.

gitleaks is still valuable and still runs; it catches secret-shaped strings
anywhere in the tree by entropy. This hook covers the one case gitleaks
structurally cannot: correctly-formed Kubernetes Secrets.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("no-plaintext-secrets: PyYAML is required (pip install pyyaml)")

# SealedSecrets are encrypted at rest and are meant to be committed.
# ExternalSecret / SecretStore / ClusterSecretStore reference secrets; they never carry them.
ALLOWED_KINDS = {"SealedSecret", "ExternalSecret", "ClusterExternalSecret",
                 "SecretStore", "ClusterSecretStore"}


def offending_documents(path: Path) -> list[str]:
    """Return a description of each document in `path` that holds literal secret data."""
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        # A file we cannot parse is not a file we can clear. Fail closed.
        return [f"unparseable YAML ({type(exc).__name__}) -- cannot verify"]

    offences = []
    for index, doc in enumerate(documents):
        for kind, name, payload in _secrets_in(doc):
            if kind in ALLOWED_KINDS:
                continue
            if kind == "Secret" and payload:
                where = f"document {index + 1}" if len(documents) > 1 else "document"
                offences.append(f"{where}: Secret/{name} carries {payload}")
    return offences


def _secrets_in(doc, name_hint="<unnamed>"):
    """Yield (kind, name, populated-field-list) for a document and any nested items.

    Handles List manifests, whose `items` are full manifests in their own right.
    """
    if not isinstance(doc, dict):
        return
    kind = doc.get("kind")
    name = (doc.get("metadata") or {}).get("name", name_hint) if isinstance(doc.get("metadata"), dict) else name_hint

    if kind in ("List", "SecretList") and isinstance(doc.get("items"), list):
        for item in doc["items"]:
            yield from _secrets_in(item, name_hint)
        return

    populated = [f for f in ("data", "stringData") if doc.get(f)]
    yield kind, name, ", ".join(f"a non-empty {f} block" for f in populated)


def main(argv: list[str]) -> int:
    failed = False
    for arg in argv:
        path = Path(arg)
        if path.suffix not in (".yaml", ".yml"):
            continue
        for offence in offending_documents(path):
            print(f"{path}: {offence}", file=sys.stderr)
            failed = True

    if failed:
        print(
            "\nA Kubernetes Secret with literal key material must never be committed to a\n"
            "repository Argo CD reconciles -- it would be applied to the cluster verbatim,\n"
            "and it stays readable in git history long after the file is deleted.\n"
            "\n"
            "Use an ExternalSecret instead. Vault holds the value; External Secrets Operator\n"
            "creates the Kubernetes Secret in-cluster at runtime; Reloader restarts the pods\n"
            "that consume it. See README.md.\n",
            file=sys.stderr,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
