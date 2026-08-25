// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package secretspec

import (
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
)

// chartSpec mirrors what deploy/helm/stackweaver/templates/shared/secrets-init-job.yaml
// renders with default values. It is the format-parity fixture for the two
// implementations this binary replaced (the kubectl/openssl shell script and
// the sprig lookup() templates).
const chartSpec = `{
  "secrets": [
    {"name":"sw-postgresql","data":[{"key":"password","gen":"alnum","len":24}]},
    {"name":"sw-storage","data":[
      {"key":"access-key","gen":"hex","len":24,"prefix":"GK"},
      {"key":"secret-key","gen":"hex","len":64}]},
    {"name":"sw-garage","data":[
      {"key":"rpc-secret","gen":"hex","len":64},
      {"key":"admin-token","gen":"alnum","len":32},
      {"key":"metrics-token","gen":"alnum","len":32}]},
    {"name":"sw-encryption","data":[{"key":"encryption-key","gen":"hex","len":64}]},
    {"name":"sw-zitadel","data":[
      {"key":"masterkey","gen":"alnum","len":32},
      {"key":"admin-password","gen":"alnum","len":16,"suffix":"!1A"},
      {"key":"admin-username","value":"admin@stackweaver.local"},
      {"key":"client-id","value":""},
      {"key":"client-secret","value":""},
      {"key":"login-service-user-token","value":""},
      {"key":"frontend-client-id","value":""},
      {"key":"webhook-idp-sync-key","value":""},
      {"key":"webhook-complement-token-key","value":""}]},
    {"name":"sw-oidc","data":[{"key":"signing-key","gen":"rsa-pem","bits":2048}]}
  ]
}`

func TestParseChartSpec(t *testing.T) {
	spec, err := Parse([]byte(chartSpec))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(spec.Secrets), 6; got != want {
		t.Fatalf("secrets = %d, want %d", got, want)
	}
	if got, want := len(spec.Secrets[4].Data), 9; got != want {
		t.Errorf("zitadel keys = %d, want %d", got, want)
	}
}

func TestParseRejectsInvalidSpecs(t *testing.T) {
	tests := map[string]string{
		"not json":          `{`,
		"no secrets":        `{"secrets":[]}`,
		"missing name":      `{"secrets":[{"data":[{"key":"a","value":"b"}]}]}`,
		"empty data":        `{"secrets":[{"name":"s","data":[]}]}`,
		"missing key":       `{"secrets":[{"name":"s","data":[{"value":"b"}]}]}`,
		"unknown generator": `{"secrets":[{"name":"s","data":[{"key":"a","gen":"uuid"}]}]}`,
		"alnum without len": `{"secrets":[{"name":"s","data":[{"key":"a","gen":"alnum"}]}]}`,
		"hex with zero len": `{"secrets":[{"name":"s","data":[{"key":"a","gen":"hex","len":0}]}]}`,
		"weak rsa":          `{"secrets":[{"name":"s","data":[{"key":"a","gen":"rsa-pem","bits":512}]}]}`,
		"duplicate secret":  `{"secrets":[{"name":"s","data":[{"key":"a","value":""}]},{"name":"s","data":[{"key":"a","value":""}]}]}`,
		"duplicate key":     `{"secrets":[{"name":"s","data":[{"key":"a","value":""},{"key":"a","value":""}]}]}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("Parse(%s) err = nil, want an error", raw)
			}
		})
	}
}

// Version skew between chart and image must not break the hook.
func TestParseIgnoresUnknownFields(t *testing.T) {
	raw := `{"secrets":[{"name":"s","future":"x","data":[{"key":"a","value":"b","rotate":true}]}]}`
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// The generated formats must be byte-compatible with what the shell script and
// the sprig templates produced, or an upgrade would hand Garage/Zitadel values
// they reject.
func TestMaterializeFormatParity(t *testing.T) {
	spec, err := Parse([]byte(chartSpec))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]map[string]*regexp.Regexp{
		"sw-postgresql": {"password": regexp.MustCompile(`^[A-Za-z0-9]{24}$`)},
		"sw-storage": {
			"access-key": regexp.MustCompile(`^GK[0-9a-f]{24}$`),
			"secret-key": regexp.MustCompile(`^[0-9a-f]{64}$`),
		},
		"sw-garage": {
			"rpc-secret":    regexp.MustCompile(`^[0-9a-f]{64}$`),
			"admin-token":   regexp.MustCompile(`^[A-Za-z0-9]{32}$`),
			"metrics-token": regexp.MustCompile(`^[A-Za-z0-9]{32}$`),
		},
		"sw-encryption": {"encryption-key": regexp.MustCompile(`^[0-9a-f]{64}$`)},
		"sw-zitadel": {
			"masterkey":      regexp.MustCompile(`^[A-Za-z0-9]{32}$`),
			"admin-password": regexp.MustCompile(`^[A-Za-z0-9]{16}!1A$`),
			"admin-username": regexp.MustCompile(`^admin@stackweaver\.local$`),
			"client-id":      regexp.MustCompile(`^$`),
			"client-secret":  regexp.MustCompile(`^$`),
		},
	}

	for _, secret := range spec.Secrets {
		data, err := secret.Materialize()
		if err != nil {
			t.Fatalf("Materialize(%s): %v", secret.Name, err)
		}
		if got, want := len(data), len(secret.Data); got != want {
			t.Errorf("%s: %d keys, want %d", secret.Name, got, want)
		}
		for key, re := range want[secret.Name] {
			if got := string(data[key]); !re.MatchString(got) {
				t.Errorf("%s/%s = %q, want match %s", secret.Name, key, got, re)
			}
		}
	}
}

// signing-key must be a PKCS#1 PEM (the `openssl genrsa` / sprig genPrivateKey
// format) so the API and both runners can load the shared workload-identity key
// and `openssl rsa -check` in the kind harness accepts it.
func TestRSAPEMRoundTrip(t *testing.T) {
	spec := SecretSpec{Name: "oidc", Data: []KeySpec{{Key: "signing-key", Gen: GenRSAPEM, Bits: 2048}}}
	data, err := spec.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	raw := data["signing-key"]
	if !strings.HasPrefix(string(raw), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Fatalf("PEM header = %q, want a PKCS#1 RSA PRIVATE KEY block", string(raw[:40]))
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		t.Errorf("trailing data after PEM block: %q", rest)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Errorf("key size = %d bits, want 2048", got)
	}
	if err := key.Validate(); err != nil {
		t.Errorf("key.Validate: %v", err)
	}
}

// rsa-pem defaults to 2048 bits when the chart omits "bits".
func TestRSAPEMDefaultBits(t *testing.T) {
	spec := SecretSpec{Name: "oidc", Data: []KeySpec{{Key: "signing-key", Gen: GenRSAPEM}}}
	data, err := spec.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	block, _ := pem.Decode(data["signing-key"])
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	if got := key.N.BitLen(); got != defaultRSABits {
		t.Errorf("key size = %d bits, want %d", got, defaultRSABits)
	}
}

func TestGeneratorsAreRandom(t *testing.T) {
	spec := SecretSpec{Name: "s", Data: []KeySpec{
		{Key: "a", Gen: GenAlnum, Len: 32},
		{Key: "h", Gen: GenHex, Len: 64},
	}}
	first, err := spec.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	second, err := spec.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	for _, key := range []string{"a", "h"} {
		if string(first[key]) == string(second[key]) {
			t.Errorf("key %q repeated across generations: %q", key, first[key])
		}
	}
}

// An odd length must still yield exactly that many hex characters.
func TestRandHexOddLength(t *testing.T) {
	got, err := randHex(7)
	if err != nil {
		t.Fatalf("randHex: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{7}$`).MatchString(got) {
		t.Errorf("randHex(7) = %q", got)
	}
}

func TestGeneratorsRejectNonPositiveLength(t *testing.T) {
	if _, err := randAlnum(0); err == nil {
		t.Error("randAlnum(0) err = nil, want an error")
	}
	if _, err := randHex(-1); err == nil {
		t.Error("randHex(-1) err = nil, want an error")
	}
}
