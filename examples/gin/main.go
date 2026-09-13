// Command gin-example is a minimal Gin server protected by Keycloak JWTs.
//
// Run it with the issuer URL of your Keycloak realm and the credentials of a
// confidential client whose service account holds the realm-management roles
// view-users and manage-users:
//
//	KEYCLOAK_ISSUER=https://sso.example.com/realms/myrealm \
//	KEYCLOAK_CLIENT_ID=my-backend \
//	KEYCLOAK_CLIENT_SECRET=... \
//	go run ./examples/gin
//
// Then call it with an access token obtained from Keycloak:
//
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/reports
//
// Users with the "admin" realm role can list all users with their realm
// roles, and grant or revoke a realm role:
//
//	curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/users
//	curl -X PUT    -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/users/$UUID/roles/editor
//	curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/users/$UUID/roles/editor
package main

import (
	"errors"
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
	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	clientSecret := os.Getenv("KEYCLOAK_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET must be set")
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// The Client fetches the realm's JWKS once at startup and refreshes it in
	// the background, and talks to the Admin REST API using the server's own
	// service account. Create it once and share it across handlers.
	kc, err := keygonomics.New(keygonomics.Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		log.Fatalf("creating keycloak client: %v", err)
	}

	r := gin.Default()

	// Public route: no token required.
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Everything under /api requires a valid Keycloak token.
	api := r.Group("/api", keygonomics.RequireAuth(kc))

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
	admin := api.Group("/admin", keygonomics.RequireRealmRole("admin"))

	admin.GET("", func(c *gin.Context) {
		uuid, _ := keygonomics.GetUUID(c)
		c.JSON(http.StatusOK, gin.H{"message": "hello, admin " + uuid})
	})

	// All users in the realm with their realm roles.
	admin.GET("/users", func(c *gin.Context) {
		users, err := kc.ListUsers(c.Request.Context())
		if err != nil {
			log.Printf("listing users: %v", err)
			c.JSON(http.StatusBadGateway, keygonomics.ErrorResponse{Error: "failed to query keycloak"})
			return
		}
		c.JSON(http.StatusOK, users)
	})

	// Grant a realm role to a user.
	admin.PUT("/users/:id/roles/:role", func(c *gin.Context) {
		err := kc.AssignRealmRole(c.Request.Context(), c.Param("id"), c.Param("role"))
		writeRoleChangeResult(c, err)
	})

	// Revoke a realm role from a user.
	admin.DELETE("/users/:id/roles/:role", func(c *gin.Context) {
		err := kc.RemoveRealmRole(c.Request.Context(), c.Param("id"), c.Param("role"))
		writeRoleChangeResult(c, err)
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

func writeRoleChangeResult(c *gin.Context, err error) {
	switch {
	case err == nil:
		c.Status(http.StatusNoContent)
	case errors.Is(err, keygonomics.ErrRoleNotFound):
		c.JSON(http.StatusNotFound, keygonomics.ErrorResponse{Error: "role not found"})
	default:
		log.Printf("changing role: %v", err)
		c.JSON(http.StatusBadGateway, keygonomics.ErrorResponse{Error: "failed to update keycloak"})
	}
}
