// Package keygonomics verifies Keycloak-issued JSON Web Tokens (JWTs),
// exposes their claims in a typed form, and provides ready-to-use Gin
// middleware for protecting routes.
//
// # Core
//
// The core API is framework-agnostic. [Verifier] fetches and caches the
// realm's JSON Web Key Set (JWKS), verifies a token's signature and
// time-based claims, and parses the Keycloak-specific claims
// (preferred_username, email, realm_access, resource_access) into a
// [Claims] value.
//
//	v, err := keygonomics.NewFromIssuer("https://sso.example.com/realms/myrealm")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	raw, ok := keygonomics.ExtractBearerToken(r.Header.Get("Authorization"))
//	if !ok {
//		// no bearer token present
//	}
//
//	claims, err := v.Verify(raw)
//	if err != nil {
//		// invalid, expired, or badly signed token
//	}
//
//	userID := claims.UUID()
//	if claims.HasRealmRole("admin") {
//		// ...
//	}
//
// # Gin middleware
//
// Attach [RequireAuth] to a router or group to reject requests without a
// valid bearer token. Chain [RequireRealmRole] or [RequireClientRole] after
// it to restrict access by Keycloak role. Inside handlers, use [GetClaims],
// [GetUUID], and [GetRealmRoles] to read the authenticated user's identity.
//
//	r := gin.Default()
//	api := r.Group("/api", keygonomics.RequireAuth(v))
//	api.GET("/me", func(c *gin.Context) {
//		uuid, _ := keygonomics.GetUUID(c)
//		c.JSON(http.StatusOK, gin.H{"uuid": uuid})
//	})
//	api.GET("/admin", keygonomics.RequireRealmRole("admin"), adminHandler)
//
// # Realm roles vs. client roles
//
// Keycloak distinguishes between realm roles, which apply across the whole
// realm and appear under the realm_access claim, and client roles, which are
// scoped to a specific client and appear under resource_access keyed by
// client ID. Use [Claims.HasRealmRole] for the former and
// [Claims.HasClientRole] for the latter.
package keygonomics
