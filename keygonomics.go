package keygonomics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is returned by [Client.Verify] (wrapped) when a token
// cannot be parsed, has an invalid signature, uses a disallowed signing
// method, or fails time-based validation.
var ErrInvalidToken = errors.New("keygonomics: invalid token")

// ErrMissingBearerToken is returned by [ExtractBearerToken] when the header
// is absent, uses a scheme other than "Bearer", or carries an empty token.
var ErrMissingBearerToken = errors.New("keygonomics: missing or malformed bearer token")

// ErrRoleNotFound is returned (wrapped) by [Client.AssignRealmRole] and
// [Client.RemoveRealmRole] when the named realm role does not exist.
var ErrRoleNotFound = errors.New("keygonomics: role not found")

// ErrAdminRequestFailed is returned (wrapped) by the admin methods of
// [Client] when Keycloak responds with a non-2xx status. The wrapping error
// includes the status code and a snippet of the response body.
var ErrAdminRequestFailed = errors.New("keygonomics: admin API request failed")

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

// User is a Keycloak user together with their realm-level roles, as returned
// by [Client.ListUsers].
type User struct {
	// ID is the user's Keycloak UUID.
	ID string `json:"id"`
	// Username is the user's login name.
	Username string `json:"username"`
	// Email is the user's email address, if any.
	Email string `json:"email,omitempty"`
	// Enabled reports whether the account is enabled.
	Enabled bool `json:"enabled"`
	// RealmRoles lists the realm-level roles directly mapped to the user.
	// It is never nil.
	RealmRoles []string `json:"realm_roles"`
}

// Config configures a [Client].
type Config struct {
	// Issuer is the realm's issuer URL, for example
	// "https://sso.example.com/realms/myrealm". It is the value of the iss
	// claim in tokens the realm issues. Required.
	Issuer string

	// ClientID and ClientSecret are the credentials of a confidential
	// Keycloak client with "Service accounts enabled". Its service account
	// must hold the realm-management roles view-users (for
	// [Client.ListUsers]) and manage-users (for [Client.AssignRealmRole] and
	// [Client.RemoveRealmRole]). Required.
	ClientID     string
	ClientSecret string

	// HTTPClient is used for requests to the Keycloak Admin REST API and
	// token endpoint. If nil, [http.DefaultClient] is used. It does not
	// affect JWKS fetching; use Keyfunc for that.
	HTTPClient *http.Client

	// Keyfunc, if set, is used to verify token signatures instead of
	// fetching the realm's JWKS. Use it for custom refresh intervals,
	// multiple JWKS URLs, or a static key set in tests.
	Keyfunc keyfunc.Keyfunc
}

// Client verifies Keycloak access tokens against a realm's JWKS and queries
// and modifies users and roles through the Keycloak Admin REST API.
//
// A Client is safe for concurrent use. Create one with [New] or [NewContext]
// and reuse it for the lifetime of the process: it caches the JWKS,
// refreshes it in the background, and caches the service-account token
// until shortly before it expires.
type Client struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	kf           keyfunc.Keyfunc

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// New creates a Client from cfg.
//
// Unless cfg.Keyfunc is set, the realm's JWKS is fetched immediately and
// refreshed periodically in the background; an error is returned if the
// initial fetch fails.
func New(cfg Config) (*Client, error) {
	return NewContext(context.Background(), cfg)
}

// NewContext is like [New] but the background JWKS refresh goroutine stops
// when ctx is cancelled.
func NewContext(ctx context.Context, cfg Config) (*Client, error) {
	issuer := strings.TrimRight(cfg.Issuer, "/")
	baseURL, realm, ok := strings.Cut(issuer, "/realms/")
	if !ok || baseURL == "" || realm == "" || strings.Contains(realm, "/") {
		return nil, fmt.Errorf("keygonomics: issuer URL %q is not of the form <base>/realms/<realm>", cfg.Issuer)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("keygonomics: client ID and secret must not be empty")
	}

	kf := cfg.Keyfunc
	if kf == nil {
		jwksURL := JWKSURL(issuer)
		// By default keyfunc only logs a failed initial fetch and keeps
		// retrying in the background. Surface it as an error instead so that
		// a misconfigured URL is caught at startup.
		failFast := false
		var err error
		kf, err = keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURL}, keyfunc.Override{
			NoErrorReturnFirstHTTPReq: &failFast,
		})
		if err != nil {
			return nil, fmt.Errorf("keygonomics: fetching JWKS from %s: %w", jwksURL, err)
		}
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		baseURL:      baseURL,
		realm:        realm,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		httpClient:   httpClient,
		kf:           kf,
	}, nil
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
func (c *Client) Verify(rawToken string) (*Claims, error) {
	if c == nil || c.kf == nil {
		return nil, errors.New("keygonomics: Client is not initialised")
	}
	if rawToken == "" {
		return nil, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, c.kf.Keyfunc,
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
// case-insensitively, as required by RFC 6750. It returns the token on
// success, or [ErrMissingBearerToken] if the header is absent, uses a
// different scheme, or carries an empty token.
func ExtractBearerToken(header string) (string, error) {
	const prefix = "bearer "
	header = strings.TrimSpace(header)
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", ErrMissingBearerToken
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", ErrMissingBearerToken
	}
	return token, nil
}

// ListUsers returns every user in the realm along with the realm roles
// directly mapped to them.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	const pageSize = 100
	users := []User{}
	for first := 0; ; first += pageSize {
		var page []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Enabled  bool   `json:"enabled"`
		}
		path := fmt.Sprintf("/admin/realms/%s/users?first=%d&max=%d", url.PathEscape(c.realm), first, pageSize)
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		for _, u := range page {
			roles, err := c.userRealmRoles(ctx, u.ID)
			if err != nil {
				return nil, err
			}
			users = append(users, User{
				ID:         u.ID,
				Username:   u.Username,
				Email:      u.Email,
				Enabled:    u.Enabled,
				RealmRoles: roles,
			})
		}
		if len(page) < pageSize {
			return users, nil
		}
	}
}

// AssignRealmRole grants the named realm role to the user with the given
// Keycloak UUID. It returns an error wrapping [ErrRoleNotFound] if the role
// does not exist.
func (c *Client) AssignRealmRole(ctx context.Context, userID, role string) error {
	return c.changeRealmRole(ctx, http.MethodPost, userID, role)
}

// RemoveRealmRole revokes the named realm role from the user with the given
// Keycloak UUID. It returns an error wrapping [ErrRoleNotFound] if the role
// does not exist.
func (c *Client) RemoveRealmRole(ctx context.Context, userID, role string) error {
	return c.changeRealmRole(ctx, http.MethodDelete, userID, role)
}

type roleRepresentation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) changeRealmRole(ctx context.Context, method, userID, role string) error {
	var rep roleRepresentation
	rolePath := fmt.Sprintf("/admin/realms/%s/roles/%s", url.PathEscape(c.realm), url.PathEscape(role))
	if err := c.do(ctx, http.MethodGet, rolePath, nil, &rep); err != nil {
		var se *adminStatusError
		if errors.As(err, &se) && se.status == http.StatusNotFound {
			return fmt.Errorf("%w: %q", ErrRoleNotFound, role)
		}
		return err
	}
	mapPath := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", url.PathEscape(c.realm), url.PathEscape(userID))
	return c.do(ctx, method, mapPath, []roleRepresentation{rep}, nil)
}

func (c *Client) userRealmRoles(ctx context.Context, userID string) ([]string, error) {
	var reps []roleRepresentation
	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", url.PathEscape(c.realm), url.PathEscape(userID))
	if err := c.do(ctx, http.MethodGet, path, nil, &reps); err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(reps))
	for _, r := range reps {
		roles = append(roles, r.Name)
	}
	return roles, nil
}

// adminStatusError carries the HTTP status of a failed admin request so
// callers can distinguish e.g. 404 from other failures. It unwraps to
// ErrAdminRequestFailed.
type adminStatusError struct {
	status int
	body   string
}

func (e *adminStatusError) Error() string {
	return fmt.Sprintf("%v: status %d: %s", ErrAdminRequestFailed, e.status, e.body)
}

func (e *adminStatusError) Unwrap() error { return ErrAdminRequestFailed }

// do performs an authenticated JSON request against the admin API. body, if
// non-nil, is JSON-encoded; out, if non-nil, receives the decoded response.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("keygonomics: encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("keygonomics: building admin request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keygonomics: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &adminStatusError{status: resp.StatusCode, body: readSnippet(resp.Body)}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("keygonomics: decoding response from %s %s: %w", method, path, err)
		}
	}
	return nil
}

// tokenExpirySkew is subtracted from a token's lifetime so that a token is
// refreshed before it actually expires, avoiding races at the boundary.
const tokenExpirySkew = 30 * time.Second

// accessToken returns a cached service-account token, fetching a new one via
// the client-credentials grant when none is cached or it is about to expire.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return c.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, url.PathEscape(c.realm))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("keygonomics: building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keygonomics: requesting service-account token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keygonomics: service-account token request: %w",
			&adminStatusError{status: resp.StatusCode, body: readSnippet(resp.Body)})
	}

	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("keygonomics: decoding token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("keygonomics: token response contained no access_token")
	}

	c.token = tr.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - tokenExpirySkew)
	return c.token, nil
}

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 512))
	return strings.TrimSpace(string(b))
}
