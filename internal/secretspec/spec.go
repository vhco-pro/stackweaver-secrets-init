// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

// Package secretspec parses and executes the SECRETS_SPEC document the Helm
// chart renders for the secrets-init Job.
//
// The split of responsibilities is deliberate: the chart owns *policy* (which
// secrets are chart-managed, which keys they carry and what shape each value
// has, honouring the secrets.*.secretName bring-your-own guards); this package
// owns *execution* and knows nothing about the chart. That keeps the generator
// unit-testable and stops a second, divergent generation implementation from
// growing anywhere else.
package secretspec

import (
	"encoding/json"
	"fmt"
)

// Generator names accepted in the "gen" field of a KeySpec.
const (
	// GenValue emits Value verbatim. It is the default when "gen" is omitted and
	// is how the chart seeds the empty placeholder keys that zitadel-init later
	// patches, plus deterministic values such as the admin username.
	GenValue = "value"
	// GenAlnum emits Len characters drawn uniformly from [A-Za-z0-9].
	GenAlnum = "alnum"
	// GenHex emits Len lowercase hexadecimal characters.
	GenHex = "hex"
	// GenRSAPEM emits a PKCS#1 RSA private key in PEM form ("RSA PRIVATE KEY"),
	// the same encoding `openssl genrsa` and sprig's genPrivateKey produced on
	// the two paths this replaces.
	GenRSAPEM = "rsa-pem"
)

// Spec is the top-level SECRETS_SPEC document.
type Spec struct {
	Secrets []SecretSpec `json:"secrets"`
}

// SecretSpec describes one Secret: its name and the keys it must carry.
// Secrets are all-or-nothing — an existing Secret is skipped whole, never
// merged key by key.
type SecretSpec struct {
	Name string    `json:"name"`
	Data []KeySpec `json:"data"`
}

// KeySpec describes one key inside a Secret.
type KeySpec struct {
	Key    string `json:"key"`
	Gen    string `json:"gen,omitempty"`
	Len    int    `json:"len,omitempty"`
	Bits   int    `json:"bits,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Suffix string `json:"suffix,omitempty"`
	Value  string `json:"value,omitempty"`
}

// Parse decodes and validates a SECRETS_SPEC document. Validation is strict:
// an unusable spec is a chart bug and must fail the hook loudly rather than
// silently create a Secret with a missing or malformed key.
func Parse(raw []byte) (*Spec, error) {
	var spec Spec
	// Unknown fields are tolerated on purpose: chart and image version-skew is
	// normal (the chart may ship a newer spec field than a pinned image knows),
	// and an ignored field is far safer than a hook that refuses to bootstrap.
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("parse SECRETS_SPEC: %w", err)
	}
	if err := spec.validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

func (s *Spec) validate() error {
	if len(s.Secrets) == 0 {
		return fmt.Errorf("SECRETS_SPEC contains no secrets")
	}
	seen := make(map[string]struct{}, len(s.Secrets))
	for i, secret := range s.Secrets {
		if secret.Name == "" {
			return fmt.Errorf("secrets[%d]: name is required", i)
		}
		if _, dup := seen[secret.Name]; dup {
			return fmt.Errorf("secrets[%d]: duplicate secret name %q", i, secret.Name)
		}
		seen[secret.Name] = struct{}{}
		if len(secret.Data) == 0 {
			return fmt.Errorf("secrets[%d] (%s): data is empty", i, secret.Name)
		}
		keys := make(map[string]struct{}, len(secret.Data))
		for j, key := range secret.Data {
			if key.Key == "" {
				return fmt.Errorf("secrets[%d] (%s).data[%d]: key is required", i, secret.Name, j)
			}
			if _, dup := keys[key.Key]; dup {
				return fmt.Errorf("secrets[%d] (%s): duplicate key %q", i, secret.Name, key.Key)
			}
			keys[key.Key] = struct{}{}
			if err := key.validate(); err != nil {
				return fmt.Errorf("secrets[%d] (%s).data[%d] (%s): %w", i, secret.Name, j, key.Key, err)
			}
		}
	}
	return nil
}

func (k KeySpec) validate() error {
	switch k.Gen {
	case "", GenValue:
		return nil
	case GenAlnum, GenHex:
		if k.Len <= 0 {
			return fmt.Errorf("gen %q requires a positive len", k.Gen)
		}
		return nil
	case GenRSAPEM:
		if k.Bits != 0 && k.Bits < 2048 {
			return fmt.Errorf("gen %q requires bits >= 2048, got %d", k.Gen, k.Bits)
		}
		return nil
	default:
		return fmt.Errorf("unknown generator %q", k.Gen)
	}
}
