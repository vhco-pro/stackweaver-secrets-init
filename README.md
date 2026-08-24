<!-- Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details. -->

<div align="center">

<img src="https://sw.vhco.pro/logo.png" alt="Stackweaver" width="150" />

# Stackweaver Secrets Init

[![Release](https://github.com/vhco-pro/stackweaver-secrets-init/actions/workflows/release.yml/badge.svg)](https://github.com/vhco-pro/stackweaver-secrets-init/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/vhco-pro/stackweaver-secrets-init?sort=semver)](https://github.com/vhco-pro/stackweaver-secrets-init/releases/latest)
[![CodeQL](https://github.com/vhco-pro/stackweaver-secrets-init/actions/workflows/codeql.yml/badge.svg)](https://github.com/vhco-pro/stackweaver-secrets-init/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vhco-pro/stackweaver-secrets-init/badge)](https://scorecard.dev/viewer/?uri=github.com/vhco-pro/stackweaver-secrets-init)
[![License](https://img.shields.io/badge/license-BSL%201.1-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-sw.vhco.pro-0ea5e9)](https://sw.vhco.pro/docs)

Secret bootstrap container for the [Stackweaver](https://sw.vhco.pro) DevOps platform. Creates the Kubernetes Secrets the Helm chart manages on your behalf, before anything else starts.

</div>

This is the public release repository for the Stackweaver Secrets Init container. It is published from the Stackweaver source tree on every release. See the [release sync architecture](https://sw.vhco.pro/docs/security/sync-architecture) for how releases are built, signed, and mirrored here.

## What it does

The Stackweaver chart runs this binary as a Job that is simultaneously a Helm `pre-install`/`pre-upgrade` hook and an ArgoCD `PreSync` hook, so plain Helm, Flux, ArgoCD and `helm template | kubectl apply` all bootstrap secrets through one code path.

The chart renders a `SECRETS_SPEC` document describing which Secrets it manages and what shape each key has; this binary executes it. For each Secret it reads, skips if present, and otherwise generates every key and creates it. **It never updates and never overwrites**, so re-running an install, syncing repeatedly or upgrading the chart can never rotate a live credential.

## Design

This is the one process in a Stackweaver release that holds secret-create RBAC, so it is deliberately minimal:

- **Zero third-party dependencies.** The binary links the Go standard library only - no Kubernetes client library, no SDKs. There is no `go.sum` because there is nothing to verify.
- **Distroless.** It ships on `gcr.io/distroless/static:nonroot`, so the image has no shell, no package manager and no OS packages to patch.
- **Least privilege.** The chart grants it `get` and `create` on Secrets and nothing else - no `update`, no `delete`, no `list`.
- **Fails loudly.** An unresolvable error exits non-zero and fails the hook, aborting the install rather than leaving a half-configured cluster.

## Usage

```bash
docker pull ghcr.io/vhco-pro/stackweaver-secrets-init:latest
```

It is not intended to be run by hand; the chart supplies `NAMESPACE` and `SECRETS_SPEC`. See the [Stackweaver documentation](https://sw.vhco.pro/docs) for deployment instructions, and [`secretsInit.image`](https://sw.vhco.pro/docs/get-started/self-hosting/kubernetes) for pointing the chart at a private mirror.
