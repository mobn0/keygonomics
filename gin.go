package keygonomics

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ClaimsContextKey is the key under which [RequireAuth] stores the verified
// *Claims in the Gin context. Prefer [GetClaims] over reading it
// directly.
const ClaimsContextKey = "keygonomics.claims"

// ErrorResponse is the JSON body written when a request is rejected by the
// middleware in this package.
type ErrorResponse struct {
	// Error is a short, stable, machine-readable message.
	Error string `json:"error"`
}

// RequireAuth returns middleware that authenticates the request using the
// bearer token in the Authorization header.
//
// If the header is missing, malformed, or the token fails verification, the
// request is aborted with 401 Unauthorized, a WWW-Authenticate header, and
// an [ErrorResponse] JSON body. On success the claims are stored in the
// context under [ClaimsContextKey] and the next handler runs.
func RequireAuth(v *Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := ExtractBearerToken(c.GetHeader("Authorization"))
		if !ok {
			c.Header("WWW-Authenticate", `Bearer realm="keycloak"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "missing or malformed bearer token"})
			return
		}

		claims, err := v.Verify(raw)
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer realm="keycloak", error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "invalid token"})
			return
		}

		c.Set(ClaimsContextKey, claims)
		c.Next()
	}
}

// RequireRealmRole returns middleware that aborts with 403 Forbidden unless
// the authenticated user holds the given Keycloak realm role.
//
// It must run after [RequireAuth]. If no claims are present in the context
// the request is aborted with 401 Unauthorized.
func RequireRealmRole(role string) gin.HandlerFunc {
	return requireRole(func(claims *Claims) bool {
		return claims.HasRealmRole(role)
	})
}

// RequireClientRole returns middleware that aborts with 403 Forbidden unless
// the authenticated user holds the given role for the given Keycloak client
// ID.
//
// It must run after [RequireAuth]. If no claims are present in the context
// the request is aborted with 401 Unauthorized.
func RequireClientRole(client, role string) gin.HandlerFunc {
	return requireRole(func(claims *Claims) bool {
		return claims.HasClientRole(client, role)
	})
}

func requireRole(allowed func(*Claims) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetClaims(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "not authenticated"})
			return
		}
		if !allowed(claims) {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "insufficient role"})
			return
		}
		c.Next()
	}
}

// GetClaims returns the verified claims stored by [RequireAuth]. The boolean
// is false if the request was not authenticated.
func GetClaims(c *gin.Context) (*Claims, bool) {
	v, ok := c.Get(ClaimsContextKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	if !ok || claims == nil {
		return nil, false
	}
	return claims, true
}

// GetUUID returns the authenticated user's Keycloak UUID (the token
// subject). The boolean is false if the request was not authenticated.
func GetUUID(c *gin.Context) (string, bool) {
	claims, ok := GetClaims(c)
	if !ok {
		return "", false
	}
	return claims.UUID(), true
}

// GetRealmRoles returns the authenticated user's realm roles. The boolean is
// false if the request was not authenticated. The slice is never nil when
// the boolean is true.
func GetRealmRoles(c *gin.Context) ([]string, bool) {
	claims, ok := GetClaims(c)
	if !ok {
		return nil, false
	}
	return claims.RealmRoles(), true
}
