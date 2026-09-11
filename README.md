# keygonomics

[![CI](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml/badge.svg)](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mobn0/keygonomics.svg)](https://pkg.go.dev/github.com/mobn0/keygonomics)

Keycloak JWT middleware for [Gin](https://github.com/gin-gonic/gin).

It verifies the bearer token on each request against your realm's public keys, rejects anything invalid or expired, and gives your handlers the user's UUID and roles. Routes can be restricted to a realm role or a client role with one line.

## Installation

```sh
go get github.com/mobn0/keygonomics
```

Requires Go 1.27 or newer.

## Setup guide

### 1. Find your realm's issuer URL

In the Keycloak admin console, open your realm and go to **Realm settings → General → Endpoints → OpenID Endpoint Configuration**. The JSON shown there has an `issuer` field. It looks like:

```
https://sso.example.com/realms/myrealm
```

This is the only piece of configuration the package needs. It is also the value of the `iss` claim in every token the realm issues, so you can copy it from a decoded token instead.

### 2. Create a Verifier at startup

The verifier downloads the realm's signing keys once and refreshes them in the background. Create it once and share it across all handlers.

```go
verifier, err := keygonomics.NewFromIssuer("https://sso.example.com/realms/myrealm")
if err != nil {
	log.Fatalf("keycloak: %v", err)
}
```

If this fails, the JWKS endpoint could not be reached. Check the URL, network access from your service to Keycloak, and TLS certificates.

### 3. Protect your routes

Attach `RequireAuth` to a router group. Every route in the group now requires a valid token and responds with `401` otherwise.

```go
r := gin.Default()

api := r.Group("/api", keygonomics.RequireAuth(verifier))
```

Routes registered on `r` directly stay public.

### 4. Read the user inside a handler

`RequireAuth` stores the verified claims in the Gin context. Use the helpers to read them.

```go
api.GET("/me", func(c *gin.Context) {
	claims, _ := keygonomics.GetClaims(c)
	c.JSON(http.StatusOK, gin.H{
		"uuid":     claims.UUID(),
		"username": claims.PreferredUsername,
		"email":    claims.Email,
		"roles":    claims.RealmRoles(),
	})
})
```

`claims.UUID()` is Keycloak's user ID. Use it as the key for anything you store about the user.

### 5. Restrict routes by role

Chain a role middleware after `RequireAuth`. Users without the role get `403`.

```go
// Realm role
api.GET("/admin", keygonomics.RequireRealmRole("admin"), adminHandler)

// Client role: first argument is the client ID, second is the role
api.GET("/reports", keygonomics.RequireClientRole("reporting-api", "reports:read"), reportsHandler)
```

Or restrict a whole group:

```go
admin := api.Group("/admin", keygonomics.RequireRealmRole("admin"))
admin.GET("/users", listUsers)
admin.DELETE("/users/:id", deleteUser)
```

Not sure whether you need a realm role or a client role? See [Realm roles vs. client roles](#realm-roles-vs-client-roles).

### 6. Run and test it

Put it together and start the server:

```go
log.Fatal(r.Run(":8080"))
```

Get a token from Keycloak (the password grant is the quickest way to test, if it's enabled on your client):

```sh
TOKEN=$(curl -s -X POST "https://sso.example.com/realms/myrealm/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=my-client -d username=alice -d password=secret \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me
```

A complete runnable app is in [examples/gin/main.go](examples/gin/main.go):

```sh
KEYCLOAK_ISSUER=https://sso.example.com/realms/myrealm go run ./examples/gin
```

### Error responses

| Situation | Status | Body |
| --- | --- | --- |
| No `Authorization` header, or not a `Bearer` scheme | `401` | `{"error":"missing or malformed bearer token"}` |
| Token is expired, tampered, or signed by an unknown key | `401` | `{"error":"invalid token"}` |
| Token is valid but lacks the required role | `403` | `{"error":"insufficient role"}` |
| Role middleware used without `RequireAuth` in front of it | `401` | `{"error":"not authenticated"}` |

## API reference

Every exported symbol in `github.com/mobn0/keygonomics`, with a minimal example. Full signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/mobn0/keygonomics).

### Verification

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

### Middleware and handler helpers

#### `RequireAuth(v *keygonomics.Verifier) gin.HandlerFunc`

The authentication middleware. Reads the `Authorization` header, verifies the token, and stores the claims in the Gin context. Aborts with `401` and a JSON error body if anything is wrong. Attach it to a group so every route beneath it is protected.

```go
api := r.Group("/api", keygonomics.RequireAuth(verifier))
api.GET("/me", meHandler) // only reached with a valid token
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

- Only asymmetric signing algorithms (RS*, PS*, ES*, EdDSA) are accepted. HMAC tokens are rejected, which prevents key-confusion attacks against the public JWKS.
- Tokens without an `exp` claim are rejected.
- Signing keys are refreshed hourly and on encountering an unknown key ID, so key rotation in Keycloak is picked up automatically.
- The `iss` and `aud` claims are not checked. If your service must only accept tokens for a specific audience, check `claims.Audience` in a small middleware of your own.

## License

Apache License 2.0. See [LICENSE](LICENSE).
