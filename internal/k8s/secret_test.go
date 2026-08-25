// Copyright (c) 2025 VH & Co BV. Licensed under the Business Source License 1.1. See LICENSE for details.

package k8s

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient points a Client at a httptest server with a retry schedule fast
// enough for unit tests (the production defaults are 45 s / 500 ms).
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &Client{
		http:        srv.Client(),
		token:       "test-token",
		apiBase:     srv.URL,
		retryBudget: 300 * time.Millisecond,
		retryBase:   5 * time.Millisecond,
	}
}

func TestGetSecretFound(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/api/v1/namespaces/sw/secrets/creds"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"password":"`+
			base64.StdEncoding.EncodeToString([]byte("s3cret"))+`"}}`)
	}))

	secret, found, err := client.GetSecret("creds", "sw")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if got := string(secret.Data["password"]); got != "s3cret" {
		t.Errorf("password = %q, want %q", got, "s3cret")
	}
}

func TestGetSecretNotFound(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"kind":"Status","code":404}`)
	}))

	secret, found, err := client.GetSecret("creds", "sw")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if found {
		t.Error("found = true, want false")
	}
	if secret != nil {
		t.Errorf("secret = %+v, want nil", secret)
	}
}

// A 401 is a definitive "no" from the API server and must surface as an error,
// never as "absent" - that distinction is the whole point of the tri-state.
func TestGetSecretUnauthorizedIsError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Unauthorized"}`)
	}))

	if _, found, err := client.GetSecret("creds", "sw"); err == nil {
		t.Fatalf("GetSecret err = nil, found = %v; want an error", found)
	}
}

func TestGetSecretMalformedJSONIsError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data": [not json`)
	}))

	if _, _, err := client.GetSecret("creds", "sw"); err == nil {
		t.Fatal("GetSecret err = nil, want a decode error")
	}
}

func TestGetSecretUndecodableValueIsError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"password":"!!!not-base64!!!"}}`)
	}))

	if _, _, err := client.GetSecret("creds", "sw"); err == nil {
		t.Fatal("GetSecret err = nil, want a base64 error")
	}
}

func TestCreateSecret(t *testing.T) {
	var body []byte
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got, want := r.URL.Path, "/api/v1/namespaces/sw/secrets"; got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"kind":"Secret"}`)
	}))

	err := client.CreateSecret("creds", "sw",
		map[string][]byte{"password": []byte("s3cret")},
		map[string]string{"app.kubernetes.io/managed-by": "secrets-init"})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}

	var sent struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Type       string `json:"type"`
		Metadata   struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	if sent.APIVersion != "v1" || sent.Kind != "Secret" || sent.Type != "Opaque" {
		t.Errorf("manifest header = %+v", sent)
	}
	if sent.Metadata.Name != "creds" || sent.Metadata.Namespace != "sw" {
		t.Errorf("metadata = %+v", sent.Metadata)
	}
	if sent.Metadata.Labels["app.kubernetes.io/managed-by"] != "secrets-init" {
		t.Errorf("labels = %+v", sent.Metadata.Labels)
	}
	if got := sent.Data["password"]; got != base64.StdEncoding.EncodeToString([]byte("s3cret")) {
		t.Errorf("data.password = %q, want base64 of s3cret", got)
	}
}

func TestCreateSecretConflictIsErrAlreadyExists(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"reason":"AlreadyExists"}`)
	}))

	err := client.CreateSecret("creds", "sw", map[string][]byte{"a": []byte("b")}, nil)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("CreateSecret err = %v, want ErrAlreadyExists", err)
	}
}

// A 409 must not be retried - it is a definitive answer, and retrying it would
// burn the whole budget on every racing pod.
func TestCreateSecretConflictIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusConflict)
	}))

	_ = client.CreateSecret("creds", "sw", map[string][]byte{"a": []byte("b")}, nil)
	if got := calls.Load(); got != 1 {
		t.Errorf("request count = %d, want 1", got)
	}
}

func TestCreateSecretServerErrorIsError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	err := client.CreateSecret("creds", "sw", map[string][]byte{"a": []byte("b")}, nil)
	if err == nil {
		t.Fatal("CreateSecret err = nil, want an error")
	}
	if errors.Is(err, ErrAlreadyExists) {
		t.Fatal("500 must not be reported as ErrAlreadyExists")
	}
}

// RBAC grants propagate asynchronously, so the first calls of a fresh hook Job
// can legitimately be forbidden. This replaces the shell `auth can-i` poll loop.
func TestForbiddenIsRetriedThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"reason":"Forbidden"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	_, found, err := client.GetSecret("creds", "sw")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if found {
		t.Error("found = true, want false")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("request count = %d, want 3", got)
	}
}

func TestPersistentServerErrorExhaustsBudget(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	_, _, err := client.GetSecret("creds", "sw")
	if err == nil {
		t.Fatal("GetSecret err = nil, want a budget-exhausted error")
	}
	if !strings.Contains(err.Error(), "giving up after") {
		t.Errorf("err = %v, want a giving-up error", err)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("request count = %d, want at least 2 attempts", got)
	}
}

