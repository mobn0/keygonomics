package keygonomics_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/mobn0/keygonomics"
)

const (
	testKID  = "kid-1"
	testUUID = "0b1f6d9e-2c3a-4d5e-8f7a-9b0c1d2e3f4a"
)

func init() {
	gin.SetMode(gin.TestMode)
}

type fixture struct {
	priv     *rsa.PrivateKey
	verifier *keygonomics.Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jwkset.NewJWKFromKey(priv.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{ALG: jwkset.AlgRS256, KID: testKID, USE: jwkset.UseSig},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	if err != nil {
		t.Fatal(err)
	}
	kf, err := keyfunc.NewJWKSetJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{priv: priv, verifier: keygonomics.NewWithKeyfunc(kf)}
}

// token signs a token with the given realm and client roles.
func (f *fixture) token(t *testing.T, realmRoles []string, clientRoles map[string][]string, exp time.Time) string {
	t.Helper()
	claims := keygonomics.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testUUID,
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		PreferredUsername: "alice",
		RealmAccess:       keygonomics.Roles{Roles: realmRoles},
		ResourceAccess:    map[string]keygonomics.Roles{},
	}
	for client, roles := range clientRoles {
		claims.ResourceAccess[client] = keygonomics.Roles{Roles: roles}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(f.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// router builds a test router exercising every middleware and accessor.
func (f *fixture) router() *gin.Engine {
	r := gin.New()

	r.GET("/public", func(c *gin.Context) {
		_, ok := keygonomics.GetClaims(c)
		c.JSON(http.StatusOK, gin.H{"authenticated": ok})
	})

	api := r.Group("/api", keygonomics.RequireAuth(f.verifier))
	api.GET("/me", func(c *gin.Context) {
		claims, _ := keygonomics.GetClaims(c)
		uuid, _ := keygonomics.GetUUID(c)
		roles, _ := keygonomics.GetRealmRoles(c)
		c.JSON(http.StatusOK, gin.H{
			"uuid":     uuid,
			"username": claims.PreferredUsername,
			"roles":    roles,
		})
	})
	api.GET("/admin", keygonomics.RequireRealmRole("admin"), okHandler)
	api.GET("/writer", keygonomics.RequireClientRole("my-api", "writer"), okHandler)

	// Role middleware wired without RequireAuth in front of it.
	r.GET("/misconfigured", keygonomics.RequireRealmRole("admin"), okHandler)

	return r
}

func okHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func do(t *testing.T, r http.Handler, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body %q: %v", w.Body.String(), err)
	}
	return body
}

func TestMiddleware(t *testing.T) {
	f := newFixture(t)
	r := f.router()
	future := time.Now().Add(time.Hour)

	admin := f.token(t, []string{"user", "admin"}, nil, future)
	user := f.token(t, []string{"user"}, nil, future)
	writer := f.token(t, []string{"user"}, map[string][]string{"my-api": {"reader", "writer"}}, future)
	reader := f.token(t, []string{"user"}, map[string][]string{"my-api": {"reader"}}, future)
	expired := f.token(t, []string{"admin"}, nil, time.Now().Add(-time.Hour))

	tests := []struct {
		name       string
		path       string
		auth       string
		wantStatus int
		wantError  string
	}{
		// RequireAuth
		{"no header", "/api/me", "", http.StatusUnauthorized, "missing or malformed bearer token"},
		{"wrong scheme", "/api/me", "Basic abc", http.StatusUnauthorized, "missing or malformed bearer token"},
		{"garbage token", "/api/me", "Bearer nope", http.StatusUnauthorized, "invalid token"},
		{"expired token", "/api/me", "Bearer " + expired, http.StatusUnauthorized, "invalid token"},
		{"valid token", "/api/me", "Bearer " + user, http.StatusOK, ""},
		{"valid token lowercase scheme", "/api/me", "bearer " + user, http.StatusOK, ""},

		// RequireRealmRole
		{"realm role present", "/api/admin", "Bearer " + admin, http.StatusOK, ""},
		{"realm role missing", "/api/admin", "Bearer " + user, http.StatusForbidden, "insufficient role"},
		{"realm role unauthenticated", "/api/admin", "", http.StatusUnauthorized, "missing or malformed bearer token"},

		// RequireClientRole
		{"client role present", "/api/writer", "Bearer " + writer, http.StatusOK, ""},
		{"client role missing", "/api/writer", "Bearer " + reader, http.StatusForbidden, "insufficient role"},
		{"client role no resource_access", "/api/writer", "Bearer " + user, http.StatusForbidden, "insufficient role"},

		// Role middleware without RequireAuth
		{"role check without auth middleware", "/misconfigured", "Bearer " + admin, http.StatusUnauthorized, "not authenticated"},

		// Unprotected route
		{"public route", "/public", "", http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := do(t, r, tt.path, tt.auth)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			body := decode(t, w)
			if tt.wantError != "" {
				if got, _ := body["error"].(string); got != tt.wantError {
					t.Errorf("error = %q, want %q", got, tt.wantError)
				}
				if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
					t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
				}
			}
			if tt.wantStatus == http.StatusUnauthorized && tt.path != "/misconfigured" {
				if w.Header().Get("WWW-Authenticate") == "" {
					t.Error("expected WWW-Authenticate header on 401")
				}
			}
		})
	}
}

func TestAccessors(t *testing.T) {
	f := newFixture(t)
	r := f.router()
	tok := f.token(t, []string{"user", "admin"}, nil, time.Now().Add(time.Hour))

	w := do(t, r, "/api/me", "Bearer "+tok)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	body := decode(t, w)
	if body["uuid"] != testUUID {
		t.Errorf("uuid = %v, want %s", body["uuid"], testUUID)
	}
	if body["username"] != "alice" {
		t.Errorf("username = %v, want alice", body["username"])
	}
	roles, _ := body["roles"].([]any)
	if len(roles) != 2 || roles[0] != "user" || roles[1] != "admin" {
		t.Errorf("roles = %v", body["roles"])
	}

	// Public route: accessors report no claims.
	w = do(t, r, "/public", "")
	if got := decode(t, w)["authenticated"]; got != false {
		t.Errorf("authenticated = %v on public route, want false", got)
	}
}

func TestAccessorsWithoutClaims(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	if claims, ok := keygonomics.GetClaims(c); ok || claims != nil {
		t.Error("GetClaims on empty context should return (nil, false)")
	}
	if uuid, ok := keygonomics.GetUUID(c); ok || uuid != "" {
		t.Error("GetUUID on empty context should return (\"\", false)")
	}
	if roles, ok := keygonomics.GetRealmRoles(c); ok || roles != nil {
		t.Error("GetRealmRoles on empty context should return (nil, false)")
	}

	// Wrong type stored under the key must not panic.
	c.Set(keygonomics.ClaimsContextKey, "not claims")
	if _, ok := keygonomics.GetClaims(c); ok {
		t.Error("GetClaims should reject a value of the wrong type")
	}
	var nilClaims *keygonomics.Claims
	c.Set(keygonomics.ClaimsContextKey, nilClaims)
	if _, ok := keygonomics.GetClaims(c); ok {
		t.Error("GetClaims should reject a nil *Claims")
	}
}

func TestAbortStopsChain(t *testing.T) {
	f := newFixture(t)
	r := gin.New()
	reached := false
	r.GET("/x", keygonomics.RequireAuth(f.verifier), func(*gin.Context) { reached = true })

	if w := do(t, r, "/x", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w.Code)
	}
	if reached {
		t.Error("handler ran after RequireAuth aborted")
	}
}
