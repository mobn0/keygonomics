# keygonomics

[![CI](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml/badge.svg)](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mobn0/keygonomics.svg)](https://pkg.go.dev/github.com/mobn0/keygonomics)

Keycloak JWT verification for Go, with ready-made [Gin](https://github.com/gin-gonic/gin) middleware.

If your Go service sits behind Keycloak, every request arrives with a bearer token and you need to answer three questions before doing anything else:

1. Is this token genuine and still valid?
2. Who is the user? (Keycloak's user ID is the token's `sub` claim, a UUID.)
3. What roles do they have, so I can allow or deny this route?

`keygonomics` answers all three in a few lines. It fetches and caches your realm's public keys (JWKS), verifies the token signature and expiry, and hands you a typed `Claims` struct with helpers for the user UUID and for realm and client roles.

Everything lives in a single package: the core verification API (JWKS caching, signature checks, claims parsing) and the Gin middleware built on top of it. The core functions don't touch Gin, so they work just as well with `net/http` or any other router.

## Installation

```sh
go get github.com/mobn0/keygonomics
```

Requires Go 1.27 or newer.

## Quick start

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mobn0/keygonomics"
)

func main() {
	// 1. Create a Verifier for your realm. This fetches the JWKS once and
	//    refreshes it in the background, so create it once and reuse it.
	verifier, err := keygonomics.NewFromIssuer("https://sso.example.com/realms/myrealm")
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()

	// 2. Require a valid token for everything under /api.
	api := r.Group("/api", keygonomics.RequireAuth(verifier))

	// 3. Read the user's identity inside a handler.
	api.GET("/me", func(c *gin.Context) {
		claims, _ := keygonomics.GetClaims(c)
		c.JSON(http.StatusOK, gin.H{
			"uuid":     claims.UUID(),
			"username": claims.PreferredUsername,
			"roles":    claims.RealmRoles(),
		})
	})

	// 4. Restrict a route to a realm role...
	api.GET("/admin", keygonomics.RequireRealmRole("admin"), func(c *gin.Context) {
		uuid, _ := keygonomics.GetUUID(c)
		c.JSON(http.StatusOK, gin.H{"admin": uuid})
	})

	// ...or to a role defined on a specific client.
	api.GET("/reports", keygonomics.RequireClientRole("reporting-api", "reports:read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"reports": []string{}})
	})

	log.Fatal(r.Run(":8080"))
}
```

A complete runnable version is in [examples/gin/main.go](examples/gin/main.go):

```sh
KEYCLOAK_ISSUER=https://sso.example.com/realms/myrealm go run ./examples/gin
```

### Responses

| Situation | Status | Body |
| --- | --- | --- |
| No `Authorization` header, or not a `Bearer` scheme | `401` | `{"error":"missing or malformed bearer token"}` |
| Token is expired, tampered, or signed by an unknown key | `401` | `{"error":"invalid token"}` |
| Token is valid but lacks the required role | `403` | `{"error":"insufficient role"}` |
| Role middleware used without `RequireAuth` in front of it | `401` | `{"error":"not authenticated"}` |

`401` responses also carry a `WWW-Authenticate: Bearer ...` header.

## Using the core without Gin

```go
verifier, err := keygonomics.NewFromIssuer("https://sso.example.com/realms/myrealm")
if err != nil {
	log.Fatal(err)
}

http.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
	raw, ok := keygonomics.ExtractBearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	claims, err := verifier.Verify(raw)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	fmt.Fprintln(w, "hello", claims.UUID())
})
```

If you already have the JWKS URL, or need custom refresh intervals or HTTP clients, use `keygonomics.New(jwksURL)` or build a [keyfunc](https://github.com/MicahParks/keyfunc) yourself and pass it to `keygonomics.NewWithKeyfunc`.

## API reference

Every exported symbol in `github.com/mobn0/keygonomics`, with a minimal example. Full signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/mobn0/keygonomics).

### Core

#### `Verifier`

Verifies Keycloak tokens against a realm's JWKS. Safe for concurrent use. Create one at startup and share it; it caches the keys and refreshes them in the background.

```go
var verifier *keygonomics.Verifier // created once, used by every handler
```

#### `NewFromIssuer(issuerURL string) (*Verifier, error)`

The usual constructor. Takes the realm's issuer URL (the same value as the `iss` claim in your tokens) and derives the JWKS endpoint from it.

```go
verifier, err := keygonomics.NewFromIssuer("https://sso.example.com/realms/myrealm")
if err != nil {
	log.Fatal(err) // JWKS could not be fetched: wrong URL, realm down, TLS problem
}
```

#### `New(jwksURL string) (*Verifier, error)`

Same as `NewFromIssuer`, but you give the JWKS URL directly. Useful if your Keycloak sits behind a proxy that rewrites paths.

```go
verifier, err := keygonomics.New("https://sso.example.com/realms/myrealm/protocol/openid-connect/certs")
```

#### `NewContext` / `NewFromIssuerContext`

Context-aware versions of `New` and `NewFromIssuer`. The background JWKS refresh goroutine stops when the context is cancelled. Use these if you shut the service down gracefully or create verifiers in tests.

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel() // stops the refresh goroutine

verifier, err := keygonomics.NewFromIssuerContext(ctx, "https://sso.example.com/realms/myrealm")
```

#### `NewWithKeyfunc(kf keyfunc.Keyfunc) *Verifier`

Wraps an existing [keyfunc](https://github.com/MicahParks/keyfunc) you built yourself. Reach for this when you need a custom refresh interval, HTTP client, several JWKS URLs, or a static key set in tests.

```go
kf, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{jwksURL}, keyfunc.Override{
	RefreshInterval: 5 * time.Minute,
})
if err != nil {
	log.Fatal(err)
}
verifier := keygonomics.NewWithKeyfunc(kf)
```

#### `JWKSURL(issuerURL string) string`

Pure helper that turns an issuer URL into the JWKS URL. Trailing slashes are stripped. `NewFromIssuer` uses it internally.

```go
u := keygonomics.JWKSURL("https://sso.example.com/realms/myrealm/")
// "https://sso.example.com/realms/myrealm/protocol/openid-connect/certs"
```

#### `(*Verifier).Verify(rawToken string) (*Claims, error)`

Parses a raw JWT, checks the signature against the JWKS, and validates `exp`, `nbf`, and `iat`. Returns the parsed claims or an error wrapping `ErrInvalidToken`.

```go
claims, err := verifier.Verify(rawToken)
if err != nil {
	// expired, bad signature, unknown key, HMAC, missing exp, garbage...
	return
}
fmt.Println(claims.UUID(), claims.PreferredUsername)
```

#### `ErrInvalidToken`

Sentinel error wrapped by every failure from `Verify`. Use it to distinguish "bad token" from other errors without inspecting strings.

```go
if errors.Is(err, keygonomics.ErrInvalidToken) {
	w.WriteHeader(http.StatusUnauthorized)
}
```

#### `ExtractBearerToken(header string) (string, bool)`

Pulls the token out of an `Authorization` header value. The `Bearer` scheme is matched case-insensitively. Returns `false` for a missing header, another scheme (`Basic ...`), or an empty token.

```go
raw, ok := keygonomics.ExtractBearerToken(r.Header.Get("Authorization"))
if !ok {
	http.Error(w, "missing bearer token", http.StatusUnauthorized)
	return
}
```

#### `Claims`

The parsed token. Embeds `jwt.RegisteredClaims` (so `Subject`, `Issuer`, `Audience`, `ExpiresAt`, and friends are available directly) and adds the Keycloak fields:

| Field | JSON claim | Type |
| --- | --- | --- |
| `PreferredUsername` | `preferred_username` | `string` |
| `Email` | `email` | `string` |
| `RealmAccess` | `realm_access` | `Roles` |
| `ResourceAccess` | `resource_access` | `map[string]Roles` |

```go
fmt.Println(claims.Subject)            // from jwt.RegisteredClaims
fmt.Println(claims.ExpiresAt.Time)     // from jwt.RegisteredClaims
fmt.Println(claims.PreferredUsername)  // "alice"
fmt.Println(claims.RealmAccess.Roles)  // ["user", "admin"]
```

#### `Roles`

The `{"roles": [...]}` object that Keycloak uses for `realm_access` and for each entry of `resource_access`. You mostly won't touch it directly; the helper methods below are more convenient. It is exported so you can build `Claims` values in your own tests.

```go
claims := keygonomics.Claims{
	RealmAccess:    keygonomics.Roles{Roles: []string{"admin"}},
	ResourceAccess: map[string]keygonomics.Roles{"my-api": {Roles: []string{"writer"}}},
}
```

#### `(*Claims).UUID() string`

The Keycloak user ID. This is just the `sub` claim, which Keycloak always populates with the user's UUID. Use it as the foreign key for anything you store about the user.

```go
userID := claims.UUID() // "8d3c0f8a-1e3b-4f6d-9a2c-6b7e8f9a0b1c"
```

#### `(*Claims).HasRealmRole(role string) bool`

Reports whether the user has a realm-level role. Case-sensitive.

```go
if !claims.HasRealmRole("admin") {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}
```

#### `(*Claims).HasClientRole(client, role string) bool`

Reports whether the user has a role on a specific client. `client` is the client ID from the Keycloak admin console.

```go
if claims.HasClientRole("reporting-api", "reports:read") {
	// show reports
}
```

#### `(*Claims).RealmRoles() []string`

All realm roles. Never returns `nil`, so it is safe to range over or encode to JSON as `[]`.

```go
for _, role := range claims.RealmRoles() {
	fmt.Println(role)
}
```

#### `(*Claims).ClientRoles(client string) []string`

All roles for one client. Never returns `nil`; an unknown client gives an empty slice.

```go
roles := claims.ClientRoles("reporting-api") // e.g. ["reports:read"], or [] if none
```

### Gin middleware

#### `RequireAuth(v *keygonomics.Verifier) gin.HandlerFunc`

The authentication middleware. Reads the `Authorization` header, verifies the token, and stores the claims in the Gin context. Aborts with `401` and a JSON error body if anything is wrong. Attach it to a group so every route beneath it is protected.

```go
api := r.Group("/api", keygonomics.RequireAuth(verifier))
api.GET("/me", meHandler) // only reached with a valid token
```

You can also attach it to a single route:

```go
r.GET("/me", keygonomics.RequireAuth(verifier), meHandler)
```

#### `RequireRealmRole(role string) gin.HandlerFunc`

Authorization middleware. Must come after `RequireAuth`. Aborts with `403` if the user lacks the realm role, or `401` if no claims are present (which means `RequireAuth` didn't run).

```go
api.GET("/admin", keygonomics.RequireRealmRole("admin"), adminHandler)

// Or for a whole group:
admin := api.Group("/admin", keygonomics.RequireRealmRole("admin"))
admin.GET("/users", listUsers)
admin.DELETE("/users/:id", deleteUser)
```

#### `RequireClientRole(client, role string) gin.HandlerFunc`

Same as `RequireRealmRole` but checks a client role. `client` is the Keycloak client ID.

```go
api.GET("/reports", keygonomics.RequireClientRole("reporting-api", "reports:read"), reportsHandler)
```

#### `GetClaims(c *gin.Context) (*keygonomics.Claims, bool)`

Returns the full claims stored by `RequireAuth`. The boolean is `false` on routes where `RequireAuth` did not run, so on protected routes you can safely ignore it.

```go
func meHandler(c *gin.Context) {
	claims, _ := keygonomics.GetClaims(c)
	c.JSON(http.StatusOK, gin.H{
		"uuid":  claims.UUID(),
		"email": claims.Email,
	})
}
```

On a route that is optionally authenticated, check the boolean:

```go
r.GET("/greeting", func(c *gin.Context) {
	if claims, ok := keygonomics.GetClaims(c); ok {
		c.String(http.StatusOK, "hello, "+claims.PreferredUsername)
		return
	}
	c.String(http.StatusOK, "hello, stranger")
})
```

#### `GetUUID(c *gin.Context) (string, bool)`

Shortcut for `GetClaims(c)` followed by `.UUID()`. Handy when all you need is the user ID.

```go
func createOrder(c *gin.Context) {
	userID, _ := keygonomics.GetUUID(c)
	order := db.CreateOrder(userID, ...)
	c.JSON(http.StatusCreated, order)
}
```

#### `GetRealmRoles(c *gin.Context) ([]string, bool)`

Shortcut for `GetClaims(c)` followed by `.RealmRoles()`. The slice is never `nil` when the boolean is `true`.

```go
roles, _ := keygonomics.GetRealmRoles(c)
c.JSON(http.StatusOK, gin.H{"roles": roles})
```

#### `ClaimsContextKey`

The string key under which `RequireAuth` stores the claims via `c.Set`. Exported so you can read the value with `c.Get` or `c.MustGet` if you prefer, but `GetClaims` does the type assertion for you and is the recommended way.

```go
claims := c.MustGet(keygonomics.ClaimsContextKey).(*keygonomics.Claims)
```

#### `ErrorResponse`

The JSON body sent on `401` and `403`. It has a single `error` field with a short, stable message. Exported so clients and tests can decode it.

```go
var body keygonomics.ErrorResponse
json.Unmarshal(w.Body.Bytes(), &body)
fmt.Println(body.Error) // "invalid token"
```

## Realm roles vs. client roles

Keycloak has two kinds of roles, and they show up in different places in the token. This trips up almost everyone at least once.

**Realm roles** are defined at the realm level (Realm settings → Realm roles) and apply across every client in the realm. They appear in the token under `realm_access`:

```json
"realm_access": { "roles": ["admin", "offline_access", "uma_authorization"] }
```

Check them with `claims.HasRealmRole("admin")` or `keygonomics.RequireRealmRole("admin")`.

**Client roles** are defined on a specific client (Clients → *your client* → Roles) and are scoped to that client. They appear under `resource_access`, keyed by the client ID:

```json
"resource_access": {
  "reporting-api": { "roles": ["reports:read"] },
  "account":       { "roles": ["manage-account", "view-profile"] }
}
```

Check them with `claims.HasClientRole("reporting-api", "reports:read")` or `keygonomics.RequireClientRole("reporting-api", "reports:read")`. The first argument is the **client ID** as shown in the Keycloak admin console, not the client's display name or its internal UUID.

Two common surprises:

- Client roles are only included in the token if the client's scope allows it. By default a client only receives its own roles plus the built-in `account` roles. If a role from another client is missing, check the client scope mappings.
- The `roles` client scope (which adds `realm_access` and `resource_access` to the token) must be assigned to the client. It is by default, but if you've customised scopes and roles are missing from the token entirely, that is the first place to look.

## Security notes

- Only asymmetric signing algorithms (RS*, PS*, ES*, EdDSA) are accepted. HMAC tokens are rejected outright, which prevents key-confusion attacks against the public JWKS.
- Tokens without an `exp` claim are rejected.
- The JWKS is refreshed hourly and on encountering an unknown key ID (rate limited), so key rotation in Keycloak is picked up automatically.
- This package verifies tokens; it does not check the `iss` or `aud` claims. If your service must only accept tokens for a specific audience, check `claims.Audience` in a handler or a small middleware of your own.

## License

Apache License 2.0. See [LICENSE](LICENSE).
