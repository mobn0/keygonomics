package keygonomics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const testKID = "test-key-1"

// fakeKeycloak is a minimal in-memory stand-in for the parts of Keycloak
// that Client uses: the realm JWKS, the token endpoint, and the slice of the
// Admin REST API that deals with users and realm role mappings.
type fakeKeycloak struct {
	t      *testing.T
	server *httptest.Server
	priv   *rsa.PrivateKey
	jwks   []byte
	kc     *Client

	mu          sync.Mutex
	tokenCalls  int
	expiresIn   int
	users       []map[string]any
	roles       map[string]string   // name -> id
	mappings    map[string][]string // userID -> role names
	failAdminAs int                 // if non-zero, every admin request returns this status
}

func newFakeKeycloak(t *testing.T) *fakeKeycloak {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	jwk, err := jwkset.NewJWKFromKey(priv.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			ALG: jwkset.AlgRS256,
			KID: testKID,
			USE: jwkset.UseSig,
		},
	})
	if err != nil {
		t.Fatalf("building JWK: %v", err)
	}
	jwks, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	if err != nil {
		t.Fatalf("marshalling JWKS: %v", err)
	}

	f := &fakeKeycloak{
		t:         t,
		priv:      priv,
		jwks:      jwks,
		expiresIn: 300,
		roles:     map[string]string{},
		mappings:  map[string][]string{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	f.kc, err = NewContext(ctx, f.config())
	if err != nil {
		t.Fatalf("creating Client: %v", err)
	}
	return f
}

func (f *fakeKeycloak) issuer() string { return f.server.URL + "/realms/test" }

func (f *fakeKeycloak) config() Config {
	return Config{Issuer: f.issuer(), ClientID: "backend", ClientSecret: "s3cret"}
}

// sign produces a token signed by the test key with the given claims.
func (k *fakeKeycloak) sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return s
}

func baseClaims(exp time.Time) Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://sso.example.com/realms/test",
			Subject:   "8d3c0f8a-1e3b-4f6d-9a2c-6b7e8f9a0b1c",
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
		PreferredUsername: "alice",
		Email:             "alice@example.com",
		RealmAccess:       Roles{Roles: []string{"user", "admin"}},
		ResourceAccess: map[string]Roles{
			"my-api": {Roles: []string{"reader", "writer"}},
		},
	}
}

func TestVerify(t *testing.T) {
	k := newFakeKeycloak(t)
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)

	tests := []struct {
		name    string
		token   func(t *testing.T) string
		wantErr bool
		check   func(t *testing.T, c *Claims)
	}{
		{
			name: "valid token",
			token: func(t *testing.T) string {
				return k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, baseClaims(future))
			},
			check: func(t *testing.T, c *Claims) {
				if got, want := c.UUID(), "8d3c0f8a-1e3b-4f6d-9a2c-6b7e8f9a0b1c"; got != want {
					t.Errorf("UUID() = %q, want %q", got, want)
				}
				if c.PreferredUsername != "alice" {
					t.Errorf("PreferredUsername = %q, want alice", c.PreferredUsername)
				}
				if c.Email != "alice@example.com" {
					t.Errorf("Email = %q, want alice@example.com", c.Email)
				}
				if !c.HasRealmRole("admin") {
					t.Error("expected realm role admin")
				}
				if !c.HasClientRole("my-api", "writer") {
					t.Error("expected client role my-api/writer")
				}
			},
		},
		{
			name: "expired token",
			token: func(t *testing.T) string {
				return k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, baseClaims(time.Now().Add(-time.Hour)))
			},
			wantErr: true,
		},
		{
			name: "missing exp",
			token: func(t *testing.T) string {
				c := baseClaims(future)
				c.ExpiresAt = nil
				return k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, c)
			},
			wantErr: true,
		},
		{
			name: "not yet valid",
			token: func(t *testing.T) string {
				c := baseClaims(future)
				c.NotBefore = jwt.NewNumericDate(time.Now().Add(30 * time.Minute))
				return k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, c)
			},
			wantErr: true,
		},
		{
			name: "signed by unknown key",
			token: func(t *testing.T) string {
				return k.sign(t, jwt.SigningMethodRS256, otherRSA, testKID, baseClaims(future))
			},
			wantErr: true,
		},
		{
			name: "unknown kid",
			token: func(t *testing.T) string {
				return k.sign(t, jwt.SigningMethodRS256, k.priv, "nope", baseClaims(future))
			},
			wantErr: true,
		},
		{
			name: "HMAC signing method rejected",
			token: func(t *testing.T) string {
				return k.sign(t, jwt.SigningMethodHS256, []byte("secret"), testKID, baseClaims(future))
			},
			wantErr: true,
		},
		{
			name: "ECDSA with wrong key rejected",
			token: func(t *testing.T) string {
				return k.sign(t, jwt.SigningMethodES256, ecKey, testKID, baseClaims(future))
			},
			wantErr: true,
		},
		{
			name: "tampered payload",
			token: func(t *testing.T) string {
				s := k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, baseClaims(future))
				// Flip a character in the middle of the payload segment.
				b := []byte(s)
				i := len(b) / 2
				if b[i] == 'a' {
					b[i] = 'b'
				} else {
					b[i] = 'a'
				}
				return string(b)
			},
			wantErr: true,
		},
		{
			name:    "empty token",
			token:   func(*testing.T) string { return "" },
			wantErr: true,
		},
		{
			name:    "garbage token",
			token:   func(*testing.T) string { return "not.a.jwt" },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := k.kc.Verify(tt.token(t))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, ErrInvalidToken) {
					t.Errorf("error %v does not wrap ErrInvalidToken", err)
				}
				if claims != nil {
					t.Errorf("expected nil claims on error, got %+v", claims)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, claims)
			}
		})
	}
}

func TestVerifyMinimalKeycloakPayload(t *testing.T) {
	// A token with no realm_access/resource_access at all must still parse,
	// and the role helpers must behave sanely.
	k := newFakeKeycloak(t)
	c := Claims{RegisteredClaims: jwt.RegisteredClaims{
		Subject:   "u1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	claims, err := k.kc.Verify(k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, c))
	if err != nil {
		t.Fatal(err)
	}
	if claims.RealmRoles() == nil || len(claims.RealmRoles()) != 0 {
		t.Errorf("RealmRoles() = %v, want empty non-nil slice", claims.RealmRoles())
	}
	if claims.ClientRoles("x") == nil || len(claims.ClientRoles("x")) != 0 {
		t.Errorf("ClientRoles(x) = %v, want empty non-nil slice", claims.ClientRoles("x"))
	}
	if claims.HasRealmRole("admin") || claims.HasClientRole("x", "y") {
		t.Error("no roles should be present")
	}
}

func TestNewIssuerParsing(t *testing.T) {
	f := newFakeKeycloak(t)
	// A static keyfunc avoids a JWKS fetch so arbitrary issuers can be tested.
	kf, err := keyfunc.NewJWKSetJSON(f.jwks)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		issuer   string
		wantBase string
		wantRlm  string
		wantErr  bool
	}{
		{"https://sso.example.com/realms/foo", "https://sso.example.com", "foo", false},
		{"https://sso.example.com/realms/foo/", "https://sso.example.com", "foo", false},
		{"http://localhost:8080/auth/realms/dev", "http://localhost:8080/auth", "dev", false},
		{"https://sso.example.com", "", "", true},
		{"https://sso.example.com/realms/", "", "", true},
		{"https://sso.example.com/realms/foo/extra", "", "", true},
		{"", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.issuer, func(t *testing.T) {
			kc, err := New(Config{Issuer: tt.issuer, ClientID: "id", ClientSecret: "secret", Keyfunc: kf})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got client %+v", kc)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if kc.baseURL != tt.wantBase || kc.realm != tt.wantRlm {
				t.Errorf("got base=%q realm=%q, want base=%q realm=%q", kc.baseURL, kc.realm, tt.wantBase, tt.wantRlm)
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	f := newFakeKeycloak(t)

	cfg := f.config()
	cfg.ClientID = ""
	if _, err := New(cfg); err == nil {
		t.Error("empty client ID should fail")
	}
	cfg = f.config()
	cfg.ClientSecret = ""
	if _, err := New(cfg); err == nil {
		t.Error("empty client secret should fail")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := New(Config{Issuer: srv.URL + "/realms/x", ClientID: "id", ClientSecret: "secret"}); err == nil {
		t.Error("New with failing JWKS endpoint should fail")
	}
}

func TestNilClient(t *testing.T) {
	var kc *Client
	if _, err := kc.Verify("x"); err == nil {
		t.Error("nil Client should return an error")
	}
	if _, err := (&Client{}).Verify("x"); err == nil {
		t.Error("zero Client should return an error")
	}
}

func TestJWKSURL(t *testing.T) {
	tests := []struct {
		issuer string
		want   string
	}{
		{"https://sso.example.com/realms/foo", "https://sso.example.com/realms/foo/protocol/openid-connect/certs"},
		{"https://sso.example.com/realms/foo/", "https://sso.example.com/realms/foo/protocol/openid-connect/certs"},
		{"http://localhost:8080/realms/dev//", "http://localhost:8080/realms/dev/protocol/openid-connect/certs"},
	}
	for _, tt := range tests {
		if got := JWKSURL(tt.issuer); got != tt.want {
			t.Errorf("JWKSURL(%q) = %q, want %q", tt.issuer, got, tt.want)
		}
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{"standard", "Bearer abc.def.ghi", "abc.def.ghi", true},
		{"lowercase scheme", "bearer abc.def.ghi", "abc.def.ghi", true},
		{"uppercase scheme", "BEARER abc.def.ghi", "abc.def.ghi", true},
		{"surrounding whitespace", "  Bearer abc.def.ghi  ", "abc.def.ghi", true},
		{"extra spaces after scheme", "Bearer   abc.def.ghi", "abc.def.ghi", true},
		{"empty header", "", "", false},
		{"scheme only", "Bearer", "", false},
		{"scheme with trailing space only", "Bearer ", "", false},
		{"basic scheme", "Basic dXNlcjpwYXNz", "", false},
		{"no scheme", "abc.def.ghi", "", false},
		{"scheme without separator", "Bearerabc.def.ghi", "", false},
		{"token contains space", "Bearer abc def", "", false},
		{"tab separator", "Bearer\tabc.def.ghi", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractBearerToken(tt.header)
			gotOK := err == nil
			if gotOK != tt.wantOK || got != tt.want {
				t.Errorf("ExtractBearerToken(%q) = (%q, err=%v), want (%q, ok=%v)", tt.header, got, err, tt.want, tt.wantOK)
			}
			if !tt.wantOK && !errors.Is(err, ErrMissingBearerToken) {
				t.Errorf("ExtractBearerToken(%q) error = %v, want ErrMissingBearerToken", tt.header, err)
			}
		})
	}
}

func TestClaimsRoleHelpers(t *testing.T) {
	c := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "uuid-123"},
		RealmAccess:      Roles{Roles: []string{"user", "admin"}},
		ResourceAccess: map[string]Roles{
			"my-api":  {Roles: []string{"reader"}},
			"account": {Roles: []string{"manage-account", "view-profile"}},
			"empty":   {},
		},
	}

	if got := c.UUID(); got != "uuid-123" {
		t.Errorf("UUID() = %q", got)
	}

	realmTests := []struct {
		role string
		want bool
	}{
		{"user", true},
		{"admin", true},
		{"Admin", false},
		{"superuser", false},
		{"", false},
	}
	for _, tt := range realmTests {
		if got := c.HasRealmRole(tt.role); got != tt.want {
			t.Errorf("HasRealmRole(%q) = %v, want %v", tt.role, got, tt.want)
		}
	}

	clientTests := []struct {
		client, role string
		want         bool
	}{
		{"my-api", "reader", true},
		{"my-api", "writer", false},
		{"account", "view-profile", true},
		{"empty", "anything", false},
		{"missing", "reader", false},
		{"", "", false},
	}
	for _, tt := range clientTests {
		if got := c.HasClientRole(tt.client, tt.role); got != tt.want {
			t.Errorf("HasClientRole(%q, %q) = %v, want %v", tt.client, tt.role, got, tt.want)
		}
	}

	if got := c.RealmRoles(); len(got) != 2 || got[0] != "user" || got[1] != "admin" {
		t.Errorf("RealmRoles() = %v", got)
	}
	if got := c.ClientRoles("account"); len(got) != 2 {
		t.Errorf("ClientRoles(account) = %v", got)
	}
	if got := c.ClientRoles("empty"); got == nil || len(got) != 0 {
		t.Errorf("ClientRoles(empty) = %v, want empty non-nil", got)
	}
	if got := c.ClientRoles("missing"); got == nil || len(got) != 0 {
		t.Errorf("ClientRoles(missing) = %v, want empty non-nil", got)
	}

	// Zero-value Claims must not panic.
	var zero Claims
	if zero.HasRealmRole("x") || zero.HasClientRole("a", "b") || len(zero.RealmRoles()) != 0 || len(zero.ClientRoles("a")) != 0 {
		t.Error("zero Claims should have no roles")
	}
}

func TestClaimsJSONShape(t *testing.T) {
	// Ensure the struct tags match the real Keycloak payload layout.
	raw := `{
		"sub": "abc",
		"exp": 4102444800,
		"preferred_username": "bob",
		"email": "bob@example.com",
		"realm_access": {"roles": ["offline_access", "uma_authorization"]},
		"resource_access": {
			"account": {"roles": ["manage-account"]},
			"backend": {"roles": ["admin"]}
		}
	}`
	var c Claims
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	if c.Subject != "abc" || c.PreferredUsername != "bob" || c.Email != "bob@example.com" {
		t.Errorf("unexpected scalar claims: %+v", c)
	}
	if !c.HasRealmRole("uma_authorization") {
		t.Error("realm_access not parsed")
	}
	if !c.HasClientRole("backend", "admin") || !c.HasClientRole("account", "manage-account") {
		t.Error("resource_access not parsed")
	}
}

func (f *fakeKeycloak) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	if r.URL.Path == "/realms/test/protocol/openid-connect/certs" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.jwks)
		return
	}

	if r.URL.Path == "/realms/test/protocol/openid-connect/token" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "backend" || r.Form.Get("client_secret") != "s3cret" {
			http.Error(w, `{"error":"unauthorized_client"}`, http.StatusUnauthorized)
			return
		}
		f.tokenCalls++
		writeJSON(map[string]any{"access_token": fmt.Sprintf("tok-%d", f.tokenCalls), "expires_in": f.expiresIn})
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/admin/realms/test/") {
		http.NotFound(w, r)
		return
	}
	if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer tok-") {
		http.Error(w, "missing bearer", http.StatusUnauthorized)
		return
	}
	if f.failAdminAs != 0 {
		http.Error(w, `{"error":"boom"}`, f.failAdminAs)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/admin/realms/test/")
	parts := strings.Split(rest, "/")

	switch {
	case r.Method == http.MethodGet && rest == "users":
		first, _ := strconv.Atoi(r.URL.Query().Get("first"))
		max, _ := strconv.Atoi(r.URL.Query().Get("max"))
		end := min(first+max, len(f.users))
		if first > len(f.users) {
			first = len(f.users)
		}
		writeJSON(f.users[first:end])

	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "roles":
		id, ok := f.roles[parts[1]]
		if !ok {
			http.Error(w, `{"error":"Could not find role"}`, http.StatusNotFound)
			return
		}
		writeJSON(map[string]string{"id": id, "name": parts[1]})

	case len(parts) == 4 && parts[0] == "users" && parts[2] == "role-mappings" && parts[3] == "realm":
		userID := parts[1]
		switch r.Method {
		case http.MethodGet:
			out := []map[string]string{}
			for _, name := range f.mappings[userID] {
				out = append(out, map[string]string{"id": f.roles[name], "name": name})
			}
			writeJSON(out)
		case http.MethodPost, http.MethodDelete:
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				http.Error(w, "expected JSON body, got "+ct, http.StatusUnsupportedMediaType)
				return
			}
			var reps []struct{ ID, Name string }
			if err := json.NewDecoder(r.Body).Decode(&reps); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for _, rep := range reps {
				if f.roles[rep.Name] != rep.ID {
					http.Error(w, "role id/name mismatch", http.StatusBadRequest)
					return
				}
				cur := f.mappings[userID]
				if r.Method == http.MethodPost {
					if !slices.Contains(cur, rep.Name) {
						f.mappings[userID] = append(cur, rep.Name)
					}
				} else {
					f.mappings[userID] = slices.DeleteFunc(cur, func(n string) bool { return n == rep.Name })
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		http.NotFound(w, r)
	}
}

func TestClientTokenCaching(t *testing.T) {
	f := newFakeKeycloak(t)
	a := f.kc
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := a.ListUsers(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenCalls != 1 {
		t.Errorf("token fetched %d times, want 1 (should be cached)", f.tokenCalls)
	}

	// Force expiry and confirm a fresh token is fetched.
	a.mu.Lock()
	a.tokenExpiry = time.Now().Add(-time.Second)
	a.mu.Unlock()
	if _, err := a.ListUsers(ctx); err != nil {
		t.Fatal(err)
	}
	if f.tokenCalls != 2 {
		t.Errorf("token fetched %d times after expiry, want 2", f.tokenCalls)
	}
}

func TestClientTokenFailure(t *testing.T) {
	f := newFakeKeycloak(t)
	cfg := f.config()
	cfg.ClientSecret = "wrong-secret"
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected error with bad credentials")
	}
	if !errors.Is(err, ErrAdminRequestFailed) {
		t.Errorf("error %v does not wrap ErrAdminRequestFailed", err)
	}
}

func TestClientListUsers(t *testing.T) {
	f := newFakeKeycloak(t)
	// More than one page (page size is 100) to exercise pagination.
	for i := 0; i < 250; i++ {
		id := fmt.Sprintf("u%03d", i)
		f.users = append(f.users, map[string]any{
			"id": id, "username": "user" + id, "email": id + "@example.com", "enabled": i%2 == 0,
		})
	}
	f.roles = map[string]string{"admin": "r-admin", "editor": "r-editor", "viewer": "r-viewer"}
	f.mappings["u000"] = []string{"admin", "editor"}
	f.mappings["u249"] = []string{"viewer"}

	users, err := f.kc.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 250 {
		t.Fatalf("got %d users, want 250", len(users))
	}

	byID := map[string]User{}
	for _, u := range users {
		byID[u.ID] = u
		if u.RealmRoles == nil {
			t.Errorf("user %s has nil RealmRoles, want non-nil", u.ID)
		}
	}
	if u := byID["u000"]; u.Username != "useru000" || u.Email != "u000@example.com" || !u.Enabled ||
		!slices.Equal(u.RealmRoles, []string{"admin", "editor"}) {
		t.Errorf("u000 = %+v", u)
	}
	if u := byID["u001"]; u.Enabled || len(u.RealmRoles) != 0 {
		t.Errorf("u001 = %+v", u)
	}
	if u := byID["u249"]; !slices.Equal(u.RealmRoles, []string{"viewer"}) {
		t.Errorf("u249 = %+v", u)
	}
}

func TestClientListUsersEmpty(t *testing.T) {
	f := newFakeKeycloak(t)
	users, err := f.kc.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if users == nil || len(users) != 0 {
		t.Errorf("got %v, want empty non-nil slice", users)
	}
}

func TestClientAssignAndRemoveRealmRole(t *testing.T) {
	f := newFakeKeycloak(t)
	f.users = []map[string]any{{"id": "u1", "username": "alice", "enabled": true}}
	f.roles = map[string]string{"editor": "r-editor", "viewer": "r-viewer"}
	f.mappings["u1"] = []string{"viewer"}
	a := f.kc
	ctx := context.Background()

	if err := a.AssignRealmRole(ctx, "u1", "editor"); err != nil {
		t.Fatalf("AssignRealmRole: %v", err)
	}
	if got := f.mappings["u1"]; !slices.Equal(got, []string{"viewer", "editor"}) {
		t.Errorf("after assign, mappings = %v", got)
	}

	if err := a.RemoveRealmRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("RemoveRealmRole: %v", err)
	}
	if got := f.mappings["u1"]; !slices.Equal(got, []string{"editor"}) {
		t.Errorf("after remove, mappings = %v", got)
	}

	// Round-trip through ListUsers to check the change is visible.
	users, err := a.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || !slices.Equal(users[0].RealmRoles, []string{"editor"}) {
		t.Errorf("ListUsers after changes = %+v", users)
	}
}

func TestClientRoleNotFound(t *testing.T) {
	f := newFakeKeycloak(t)
	f.roles = map[string]string{"editor": "r-editor"}
	a := f.kc
	ctx := context.Background()

	for _, fn := range []struct {
		name string
		call func() error
	}{
		{"assign", func() error { return a.AssignRealmRole(ctx, "u1", "nope") }},
		{"remove", func() error { return a.RemoveRealmRole(ctx, "u1", "nope") }},
	} {
		t.Run(fn.name, func(t *testing.T) {
			err := fn.call()
			if err == nil {
				t.Fatal("expected error for unknown role")
			}
			if !errors.Is(err, ErrRoleNotFound) {
				t.Errorf("error %v does not wrap ErrRoleNotFound", err)
			}
		})
	}
	if len(f.mappings["u1"]) != 0 {
		t.Errorf("mappings should be untouched, got %v", f.mappings["u1"])
	}
}

func TestClientServerError(t *testing.T) {
	f := newFakeKeycloak(t)
	f.failAdminAs = http.StatusForbidden
	a := f.kc
	ctx := context.Background()

	_, err := a.ListUsers(ctx)
	if err == nil || !errors.Is(err, ErrAdminRequestFailed) {
		t.Errorf("ListUsers error = %v, want ErrAdminRequestFailed", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q should mention the status code", err)
	}
	if err := a.AssignRealmRole(ctx, "u1", "editor"); err == nil || !errors.Is(err, ErrAdminRequestFailed) {
		t.Errorf("AssignRealmRole error = %v, want ErrAdminRequestFailed", err)
	}
	if errors.Is(err, ErrRoleNotFound) {
		t.Error("a 403 must not be reported as ErrRoleNotFound")
	}
}
