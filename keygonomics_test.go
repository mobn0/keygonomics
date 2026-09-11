package keygonomics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

const testKID = "test-key-1"

// testKeys holds a generated RSA key pair and a JWKS server that publishes
// its public half.
type testKeys struct {
	priv     *rsa.PrivateKey
	server   *httptest.Server
	verifier *Verifier
}

func newTestKeys(t *testing.T) *testKeys {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	v, err := NewContext(ctx, server.URL)
	if err != nil {
		t.Fatalf("creating Verifier: %v", err)
	}
	return &testKeys{priv: priv, server: server, verifier: v}
}

// sign produces a token signed by the test key with the given claims.
func (k *testKeys) sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.Claims) string {
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
	k := newTestKeys(t)
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
			claims, err := k.verifier.Verify(tt.token(t))
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
	k := newTestKeys(t)
	c := Claims{RegisteredClaims: jwt.RegisteredClaims{
		Subject:   "u1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	claims, err := k.verifier.Verify(k.sign(t, jwt.SigningMethodRS256, k.priv, testKID, c))
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

func TestNewErrors(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("New(\"\") should fail")
	}
	if _, err := NewFromIssuer(""); err == nil {
		t.Error("NewFromIssuer(\"\") should fail")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := New(srv.URL); err == nil {
		t.Error("New with failing JWKS endpoint should fail")
	}
}

func TestNilVerifier(t *testing.T) {
	var v *Verifier
	if _, err := v.Verify("x"); err == nil {
		t.Error("nil Verifier should return an error")
	}
	if _, err := (&Verifier{}).Verify("x"); err == nil {
		t.Error("zero Verifier should return an error")
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
			got, ok := ExtractBearerToken(tt.header)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("ExtractBearerToken(%q) = (%q, %v), want (%q, %v)", tt.header, got, ok, tt.want, tt.wantOK)
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
