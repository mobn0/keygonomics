package keygonomics

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is returned by [Verifier.Verify] (wrapped) when a token
// cannot be parsed, has an invalid signature, uses a disallowed signing
// method, or fails time-based validation.
var ErrInvalidToken = errors.New("keygonomics: invalid token")

// allowedSigningMethods lists the asymmetric algorithms accepted for
// verification. Keycloak signs access tokens with RS256 by default but can be
// configured to use other RSA, RSA-PSS, or ECDSA algorithms. Symmetric (HMAC)
// algorithms are deliberately excluded: accepting them alongside a public
// JWKS would allow key-confusion attacks.
var allowedSigningMethods = []string{
	jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS384.Alg(), jwt.SigningMethodRS512.Alg(),
	jwt.SigningMethodPS256.Alg(), jwt.SigningMethodPS384.Alg(), jwt.SigningMethodPS512.Alg(),
	jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg(),
	jwt.SigningMethodEdDSA.Alg(),
}

// Roles holds a list of role names. It is the shape of the realm_access
// claim and of each entry in the resource_access claim.
type Roles struct {
	// Roles is the list of role names granted to the subject.
	Roles []string `json:"roles"`
}

// Claims is the set of claims carried by a Keycloak access token.
//
// It embeds [jwt.RegisteredClaims] for the standard fields (iss, sub, aud,
// exp, nbf, iat, jti) and adds the Keycloak-specific fields that are most
// commonly needed by applications.
type Claims struct {
	jwt.RegisteredClaims

	// PreferredUsername is the preferred_username claim: the user's login
	// name as configured in Keycloak.
	PreferredUsername string `json:"preferred_username,omitempty"`

	// Email is the email claim. It is only present if the "email" scope was
	// requested and the user has an email address.
	Email string `json:"email,omitempty"`

	// RealmAccess is the realm_access claim, containing the realm-level
	// roles granted to the user.
	RealmAccess Roles `json:"realm_access"`

	// ResourceAccess is the resource_access claim, mapping a Keycloak client
	// ID to the client-level roles granted to the user for that client.
	ResourceAccess map[string]Roles `json:"resource_access"`
}

// UUID returns the Keycloak user ID, which is the token's subject (sub)
// claim. Keycloak user IDs are UUIDs.
func (c *Claims) UUID() string {
	return c.Subject
}

// RealmRoles returns the realm-level roles granted to the user. The returned
// slice is never nil.
func (c *Claims) RealmRoles() []string {
	if c.RealmAccess.Roles == nil {
		return []string{}
	}
	return c.RealmAccess.Roles
}

// ClientRoles returns the roles granted to the user for the given Keycloak
// client ID. The returned slice is never nil; an unknown client yields an
// empty slice.
func (c *Claims) ClientRoles(client string) []string {
	roles, ok := c.ResourceAccess[client]
	if !ok || roles.Roles == nil {
		return []string{}
	}
	return roles.Roles
}

// HasRealmRole reports whether the user has the given realm-level role.
func (c *Claims) HasRealmRole(role string) bool {
	return slices.Contains(c.RealmAccess.Roles, role)
}

// HasClientRole reports whether the user has the given role for the given
// Keycloak client ID.
func (c *Claims) HasClientRole(client, role string) bool {
	return slices.Contains(c.ClientRoles(client), role)
}

// Verifier verifies Keycloak access tokens against a realm's JWKS.
//
// A Verifier is safe for concurrent use. Create one with [New],
// [NewFromIssuer], or [NewWithKeyfunc] and reuse it for the lifetime of the
// process: it caches the JWKS and refreshes it in the background.
type Verifier struct {
	kf keyfunc.Keyfunc
}

// New creates a Verifier that fetches signing keys from the given JWKS URL.
//
// The JWKS is fetched immediately and refreshed periodically in the
// background. An error is returned if the initial fetch fails.
func New(jwksURL string) (*Verifier, error) {
	return NewContext(context.Background(), jwksURL)
}

// NewContext is like [New] but the background JWKS refresh goroutine stops
// when ctx is cancelled.
func NewContext(ctx context.Context, jwksURL string) (*Verifier, error) {
	if jwksURL == "" {
		return nil, errors.New("keygonomics: JWKS URL must not be empty")
	}
	// By default keyfunc only logs a failed initial fetch and keeps retrying
	// in the background. Surface it as an error instead so that a
	// misconfigured URL is caught at startup.
	failFast := false
	kf, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURL}, keyfunc.Override{
		NoErrorReturnFirstHTTPReq: &failFast,
	})
	if err != nil {
		return nil, fmt.Errorf("keygonomics: fetching JWKS from %s: %w", jwksURL, err)
	}
	return &Verifier{kf: kf}, nil
}

// NewFromIssuer creates a Verifier for a Keycloak realm given its issuer
// URL, for example "https://sso.example.com/realms/myrealm". The JWKS URL
// is derived by appending "/protocol/openid-connect/certs".
func NewFromIssuer(issuerURL string) (*Verifier, error) {
	return NewFromIssuerContext(context.Background(), issuerURL)
}

// NewFromIssuerContext is like [NewFromIssuer] but the background JWKS
// refresh goroutine stops when ctx is cancelled.
func NewFromIssuerContext(ctx context.Context, issuerURL string) (*Verifier, error) {
	if issuerURL == "" {
		return nil, errors.New("keygonomics: issuer URL must not be empty")
	}
	return NewContext(ctx, JWKSURL(issuerURL))
}

// NewWithKeyfunc creates a Verifier from an existing [keyfunc.Keyfunc]. Use
// this when you need custom keyfunc options (refresh intervals, HTTP client,
// multiple JWKS URLs) or a static key set for testing.
func NewWithKeyfunc(kf keyfunc.Keyfunc) *Verifier {
	return &Verifier{kf: kf}
}

// JWKSURL returns the JWKS endpoint for a Keycloak realm issuer URL. Trailing
// slashes on issuerURL are ignored.
func JWKSURL(issuerURL string) string {
	return strings.TrimRight(issuerURL, "/") + "/protocol/openid-connect/certs"
}

// Verify parses rawToken, verifies its signature against the JWKS, and
// validates its time-based claims (exp, nbf, iat). On success it returns the
// parsed claims.
//
// Tokens without an exp claim are rejected. Only asymmetric signing
// algorithms are accepted. Any failure is reported as an error wrapping
// [ErrInvalidToken].
func (v *Verifier) Verify(rawToken string) (*Claims, error) {
	if v == nil || v.kf == nil {
		return nil, errors.New("keygonomics: Verifier is not initialised")
	}
	if rawToken == "" {
		return nil, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, v.kf.Keyfunc,
		jwt.WithValidMethods(allowedSigningMethods),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ExtractBearerToken extracts the token from an HTTP Authorization header
// value of the form "Bearer <token>". The scheme is matched
// case-insensitively, as required by RFC 6750. It returns the token and true
// on success, or an empty string and false if the header is absent, uses a
// different scheme, or carries an empty token.
func ExtractBearerToken(header string) (string, bool) {
	const prefix = "bearer "
	header = strings.TrimSpace(header)
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
