// Package keygonomics verifies Keycloak-issued JSON Web Tokens (JWTs),
// exposes their claims in a typed form, manages users and their realm roles
// through the Keycloak Admin REST API, and provides ready-to-use Gin
// middleware for protecting routes.
//
// # Client
//
// A single [Client] does everything. It fetches and caches the realm's JSON
// Web Key Set (JWKS) to verify tokens, and authenticates to the Admin REST
// API with the client-credentials grant to list users and change their
// roles. Create one at startup and share it.
//
//	kc, err := keygonomics.New(keygonomics.Config{
//		Issuer:       "https://sso.example.com/realms/myrealm",
//		ClientID:     "my-backend",
//		ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Verifying tokens
//
// [Client.Verify] checks a token's signature and time-based claims and
// parses the Keycloak-specific claims (preferred_username, email,
// realm_access, resource_access) into a [Claims] value.
//
//	raw, err := keygonomics.ExtractBearerToken(r.Header.Get("Authorization"))
//	if err != nil {
//		// no bearer token present
//	}
//
//	claims, err := kc.Verify(raw)
//	if err != nil {
//		// invalid, expired, or badly signed token
//	}
//
//	userID := claims.UUID()
//	if claims.HasRealmRole("admin") {
//		// ...
//	}
//
// # Managing users and roles
//
// [Client.ListUsers] returns every user in the realm with their realm
// roles. [Client.AssignRealmRole] and [Client.RemoveRealmRole] grant and
// revoke a realm role for a user.
//
//	users, err := kc.ListUsers(ctx)
//	err = kc.AssignRealmRole(ctx, userID, "editor")
//	err = kc.RemoveRealmRole(ctx, userID, "editor")
//
// # Gin middleware
//
// Attach [RequireAuth] to a router or group to reject requests without a
// valid bearer token. Chain [RequireRealmRole] or [RequireClientRole] after
// it to restrict access by Keycloak role. Inside handlers, use [GetClaims],
// [GetUUID], and [GetRealmRoles] to read the authenticated user's identity.
//
//	r := gin.Default()
//	api := r.Group("/api", keygonomics.RequireAuth(kc))
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
