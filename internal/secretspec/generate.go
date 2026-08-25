// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package secretspec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
)

// alnumAlphabet is the [A-Za-z0-9] alphabet used by the alnum generator. It
// matches what the shell (`tr -dc 'A-Za-z0-9'`) and sprig (randAlphaNum) paths
// produced, so generated credentials keep the same shape as before.
const alnumAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// defaultRSABits is used when a rsa-pem key omits "bits".
const defaultRSABits = 2048

// Materialize generates every key of the Secret. It is only called once the
// Secret has been confirmed absent, so it never sees an existing value.
func (s SecretSpec) Materialize() (map[string][]byte, error) {
	data := make(map[string][]byte, len(s.Data))
	for _, key := range s.Data {
		value, err := key.generate()
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", key.Key, err)
		}
		data[key.Key] = []byte(value)
	}
	return data, nil
}

// generate produces the value for one key. Prefix and suffix compose with every
// generator (e.g. the Garage-format access key is prefix "GK" + 24 hex chars,
// the Zitadel admin password is 16 alnum chars + the "!1A" complexity suffix).
func (k KeySpec) generate() (string, error) {
	var body string
	var err error

	switch k.Gen {
	case "", GenValue:
		body = k.Value
	case GenAlnum:
		body, err = randAlnum(k.Len)
	case GenHex:
		body, err = randHex(k.Len)
	case GenRSAPEM:
		bits := k.Bits
		if bits == 0 {
			bits = defaultRSABits
		}
		body, err = rsaPrivateKeyPEM(bits)
	default:
		return "", fmt.Errorf("unknown generator %q", k.Gen)
	}
	if err != nil {
		return "", err
	}
	return k.Prefix + body + k.Suffix, nil
}

// randAlnum returns n characters drawn uniformly from alnumAlphabet.
// crypto/rand.Int rejects the biased tail, so the distribution is exact.
func randAlnum(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("alnum length must be positive, got %d", n)
	}
	limit := big.NewInt(int64(len(alnumAlphabet)))
	out := make([]byte, n)
	for i := range out {
		idx, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("read random source: %w", err)
		}
		out[i] = alnumAlphabet[idx.Int64()]
	}
	return string(out), nil
}

// randHex returns n lowercase hexadecimal characters.
func randHex(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("hex length must be positive, got %d", n)
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random source: %w", err)
	}
	return hex.EncodeToString(buf)[:n], nil
}

// rsaPrivateKeyPEM returns a fresh RSA private key as a PKCS#1 PEM block.
// PKCS#1 ("RSA PRIVATE KEY") is what `openssl genrsa` and sprig's
// genPrivateKey emitted on the two paths this replaces, and the consumer
// (core/services/oidc) accepts PKCS#1 as well as PKCS#8.
func rsaPrivateKeyPEM(bits int) (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", fmt.Errorf("generate RSA-%d key: %w", bits, err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block)), nil
}
