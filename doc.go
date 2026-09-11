// Package keygonomics verifies Keycloak-issued JSON Web Tokens (JWTs) and
// exposes their claims in a typed, convenient form.
//
// The package is framework-agnostic: it knows nothing about HTTP routers or
// middleware. It fetches and caches the realm's JSON Web Key Set (JWKS),
// verifies a token's signature and time-based claims, and parses the
// Keycloak-specific claims (preferred_username, email, realm_access,
// resource_access) into a [Claims] value.
//
// Framework adapters live in subpackages. The Gin adapter is in
// github.com/mobn0/keygonomics/gin.
//
// # Usage
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
// # Realm roles vs. client roles
//
// Keycloak distinguishes between realm roles, which apply across the whole
// realm and appear under the realm_access claim, and client roles, which are
// scoped to a specific client and appear under resource_access keyed by
// client ID. Use [Claims.HasRealmRole] for the former and
// [Claims.HasClientRole] for the latter.
package keygonomics
