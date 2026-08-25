// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Command secrets-init bootstraps the Kubernetes Secrets the Stackweaver chart
// manages on the user's behalf.
//
// It runs as a Job that is simultaneously a Helm pre-install/pre-upgrade hook
// and an ArgoCD PreSync hook, so plain Helm, Flux, ArgoCD and
// `helm template | kubectl apply` all bootstrap through exactly one code path.
// The chart renders the SECRETS_SPEC document (see internal/secretspec); this
// binary only executes it: for each Secret, read it, skip it if it exists, and
// otherwise generate every key and create it. Never update, never overwrite.
//
// It links the standard library only — no Zitadel SDK, no gRPC, no client-go —
// because this is the one process in the release that holds secret-create RBAC.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/michielvha/stackweaver/scripts/secrets-init/internal/k8s"
	"github.com/michielvha/stackweaver/scripts/secrets-init/internal/secretspec"
)

// managedLabels mark the Secrets this binary creates. They are unmanaged by
// Helm by design (created at runtime, never in the release manifest), so these
// labels are the only way to tell them apart from user-supplied Secrets.
var managedLabels = map[string]string{
	"app.kubernetes.io/managed-by": "secrets-init",
	"app.kubernetes.io/part-of":    "stackweaver",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ secrets-init: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	namespace, err := resolveNamespace()
	if err != nil {
		return err
	}

	raw := os.Getenv("SECRETS_SPEC")
	if strings.TrimSpace(raw) == "" {
		return errors.New("SECRETS_SPEC is empty; the chart must render it")
	}
	spec, err := secretspec.Parse([]byte(raw))
	if err != nil {
		return err
	}

	client, err := k8s.NewClient()
	if err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}

	fmt.Printf("secrets-init: reconciling %d secret(s) in namespace %q\n", len(spec.Secrets), namespace)

	var created, skipped int
	for _, secret := range spec.Secrets {
		// Tri-state read: an error here means "unknown", and creating on unknown
		// is exactly the overwrite hazard this design exists to prevent.
		_, found, err := client.GetSecret(secret.Name, namespace)
		if err != nil {
			return err
		}
		if found {
			fmt.Printf("  ✔ %s already exists, skipping\n", secret.Name)
			skipped++
			continue
		}

		data, err := secret.Materialize()
		if err != nil {
			return fmt.Errorf("generate secret %q: %w", secret.Name, err)
		}

		switch err := client.CreateSecret(secret.Name, namespace, data, managedLabels); {
		case errors.Is(err, k8s.ErrAlreadyExists):
			// Another writer won the race; the secret exists and was not touched.
			fmt.Printf("  ✔ %s created concurrently, skipping\n", secret.Name)
			skipped++
		case err != nil:
			return err
		default:
			fmt.Printf("  ✚ %s created (%d key(s))\n", secret.Name, len(data))
			created++
		}
	}

	fmt.Printf("secrets-init: complete — %d created, %d skipped\n", created, skipped)
	return nil
}

// resolveNamespace prefers the NAMESPACE env var the chart sets from
// .Release.Namespace, falling back to the projected service-account namespace.
func resolveNamespace() (string, error) {
	if ns := strings.TrimSpace(os.Getenv("NAMESPACE")); ns != "" {
		return ns, nil
	}
	b, err := os.ReadFile(k8s.NamespacePath)
	if err != nil {
		return "", fmt.Errorf("NAMESPACE is unset and reading %s failed: %w", k8s.NamespacePath, err)
	}
	ns := strings.TrimSpace(string(b))
	if ns == "" {
		return "", errors.New("NAMESPACE is unset and the service-account namespace file is empty")
	}
	return ns, nil
}
