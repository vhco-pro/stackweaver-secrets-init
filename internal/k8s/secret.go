// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package k8s

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrAlreadyExists is returned by CreateSecret when the API server answers 409,
// i.e. another writer created the same Secret concurrently. On a bootstrap path
// that is success, not failure: the secret exists and nothing was overwritten.
var ErrAlreadyExists = errors.New("secret already exists")

// Secret is the subset of a core/v1 Secret this client needs: the name and the
// base64-decoded data map.
type Secret struct {
	Name string
	Data map[string][]byte
}

// GetSecret reads a Secret and reports its existence tri-state:
//
//	(secret, true,  nil)   the Secret exists
//	(nil,    false, nil)   the Secret does not exist (HTTP 404)
//	(nil,    false, err)   the answer is unknown (RBAC, network, malformed body)
//
// The third case is the whole point of the tri-state: a create path must never
// read "I could not tell" as "absent, go ahead and write".
func (k *Client) GetSecret(secretName, namespace string) (*Secret, bool, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", k.apiBase, namespace, secretName)
	res, err := k.do(http.MethodGet, url, "", nil)
	if err != nil {
		return nil, false, fmt.Errorf("get secret %q: %w", secretName, err)
	}
	if res.status == http.StatusNotFound {
		return nil, false, nil
	}
	if res.status < 200 || res.status >= 300 {
		return nil, false, fmt.Errorf("get secret %q returned HTTP %d: %s",
			secretName, res.status, strings.TrimSpace(string(res.body)))
	}

	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(res.body, &payload); err != nil {
		return nil, false, fmt.Errorf("decode secret %q: %w", secretName, err)
	}

	secret := &Secret{Name: secretName, Data: make(map[string][]byte, len(payload.Data))}
	for key, encoded := range payload.Data {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, false, fmt.Errorf("decode key %q of secret %q: %w", key, secretName, err)
		}
		secret.Data[key] = decoded
	}
	return secret, true, nil
}

// CreateSecret creates an Opaque Secret with the given data and labels.
// A 409 response is returned as ErrAlreadyExists so callers can treat the
// concurrent-create race as success.
func (k *Client) CreateSecret(secretName, namespace string, data map[string][]byte, labels map[string]string) error {
	encoded := make(map[string]string, len(data))
	for key, value := range data {
		encoded[key] = base64.StdEncoding.EncodeToString(value)
	}

	metadata := map[string]any{"name": secretName, "namespace": namespace}
	if len(labels) > 0 {
		metadata["labels"] = labels
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   metadata,
		"type":       "Opaque",
		"data":       encoded,
	})
	if err != nil {
		return fmt.Errorf("marshal secret %q: %w", secretName, err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", k.apiBase, namespace)
	res, err := k.do(http.MethodPost, url, "application/json", body)
	if err != nil {
		return fmt.Errorf("create secret %q: %w", secretName, err)
	}
	if res.status == http.StatusConflict {
		return ErrAlreadyExists
	}
	if res.status < 200 || res.status >= 300 {
		return fmt.Errorf("create secret %q returned HTTP %d: %s",
			secretName, res.status, strings.TrimSpace(string(res.body)))
	}
	return nil
}
