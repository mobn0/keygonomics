package keygonomics

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrNoClaims is returned by [GetClaims], [GetUUID], and [GetRealmRoles]
// when no verified claims are present in the Gin context, meaning
// [RequireAuth] has not run for the current request.
var ErrNoClaims = errors.New("keygonomics: no claims in context")

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
func RequireAuth(kc *Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := ExtractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer realm="keycloak"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: "missing or malformed bearer token"})
			return
		}

		claims, err := kc.Verify(raw)
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
		claims, err := GetClaims(c)
		if err != nil {
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

// GetClaims returns the verified claims stored by [RequireAuth], or
// [ErrNoClaims] if the request was not authenticated.
func GetClaims(c *gin.Context) (*Claims, error) {
	v, ok := c.Get(ClaimsContextKey)
	if !ok {
		return nil, ErrNoClaims
	}
	claims, ok := v.(*Claims)
	if !ok || claims == nil {
		return nil, ErrNoClaims
	}
	return claims, nil
}

// GetUUID returns the authenticated user's Keycloak UUID (the token
// subject), or [ErrNoClaims] if the request was not authenticated.
func GetUUID(c *gin.Context) (string, error) {
	claims, err := GetClaims(c)
	if err != nil {
		return "", err
	}
	return claims.UUID(), nil
}

// GetRealmRoles returns the authenticated user's realm roles, or
// [ErrNoClaims] if the request was not authenticated. The slice is never
// nil on success.
func GetRealmRoles(c *gin.Context) ([]string, error) {
	claims, err := GetClaims(c)
	if err != nil {
		return nil, err
	}
	return claims.RealmRoles(), nil
}
