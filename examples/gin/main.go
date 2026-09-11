// Command gin-example is a minimal Gin server protected by Keycloak JWTs.
//
// Run it with the issuer URL of your Keycloak realm:
//
//	KEYCLOAK_ISSUER=https://sso.example.com/realms/myrealm go run ./examples/gin
//
// Then call it with an access token obtained from Keycloak:
//
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/reports
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/mobn0/keygonomics"
)

func main() {
	issuer := os.Getenv("KEYCLOAK_ISSUER")
	if issuer == "" {
		log.Fatal("KEYCLOAK_ISSUER must be set, e.g. https://sso.example.com/realms/myrealm")
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// The Verifier fetches the realm's JWKS once at startup and refreshes it
	// in the background. Create it once and share it across handlers.
	verifier, err := keygonomics.NewFromIssuer(issuer)
	if err != nil {
		log.Fatalf("creating verifier: %v", err)
	}

	r := gin.Default()

	// Public route: no token required.
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Everything under /api requires a valid Keycloak token.
	api := r.Group("/api", keygonomics.RequireAuth(verifier))

	// Any authenticated user can see their own identity.
	api.GET("/me", func(c *gin.Context) {
		claims, _ := keygonomics.GetClaims(c)
		c.JSON(http.StatusOK, gin.H{
			"uuid":        claims.UUID(),
			"username":    claims.PreferredUsername,
			"email":       claims.Email,
			"realm_roles": claims.RealmRoles(),
		})
	})

	// Only users with the "admin" realm role.
	api.GET("/admin", keygonomics.RequireRealmRole("admin"), func(c *gin.Context) {
		uuid, _ := keygonomics.GetUUID(c)
		c.JSON(http.StatusOK, gin.H{"message": "hello, admin " + uuid})
	})

	// Only users with the "reports:read" role on the "reporting-api" client.
	api.GET("/reports", keygonomics.RequireClientRole("reporting-api", "reports:read"), func(c *gin.Context) {
		roles, _ := keygonomics.GetRealmRoles(c)
		c.JSON(http.StatusOK, gin.H{"reports": []string{}, "your_realm_roles": roles})
	})

	log.Printf("listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
