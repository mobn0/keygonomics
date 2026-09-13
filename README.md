# keygonomics

[![CI](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml/badge.svg)](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mobn0/keygonomics.svg)](https://pkg.go.dev/github.com/mobn0/keygonomics)

Keycloak client and JWT middleware for [Gin](https://github.com/gin-gonic/gin).

One `Client` does two jobs. It verifies the bearer token on each request against your realm's public keys, rejects anything invalid or expired, and gives your handlers the user's UUID and roles; routes can be restricted to a realm role or a client role with one line. It also talks to the Keycloak Admin REST API with your service's own credentials, so your server can list every user in the realm with their roles and grant or revoke realm roles.

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

It is also the value of the `iss` claim in every token the realm issues, so you can copy it from a decoded token instead.

### 2. Create a client for your service

Your server needs its own identity in Keycloak to call the Admin REST API. In the admin console go to **Clients → Create client**:

- **Client authentication**: on (this makes it a confidential client with a secret)
- **Service accounts roles**: on

Save it, then open the **Service accounts roles** tab and assign the `realm-management` client roles `view-users` (to list users) and `manage-users` (to change roles). Copy the client ID and the secret from the **Credentials** tab.

### 3. Create the Client at startup

The client downloads the realm's signing keys once and refreshes them in the background, and fetches a service-account token the first time it talks to the Admin API. Create it once and share it across all handlers.

```go
kc, err := keygonomics.New(keygonomics.Config{
	Issuer:       "https://sso.example.com/realms/myrealm",
	ClientID:     "my-backend",
	ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
})
if err != nil {
	log.Fatalf("keycloak: %v", err)
}
```

If this fails, the JWKS endpoint could not be reached. Check the issuer URL, network access from your service to Keycloak, and TLS certificates. Bad client credentials are not detected here; they surface as an error from the first Admin API call.

### 4. Protect your routes

Attach `RequireAuth` to a router group. Every route in the group now requires a valid token and responds with `401` otherwise.

```go
r := gin.Default()

api := r.Group("/api", keygonomics.RequireAuth(kc))
```

Routes registered on `r` directly stay public.

### 5. Read the user inside a handler

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

### 6. Restrict routes by role

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

### 7. Manage users and roles

The same client lists every user in the realm with their realm roles, and grants or revokes a realm role. These calls use your service's credentials from step 2, not the calling user's token, so guard the routes that expose them.

```go
admin := api.Group("/admin", keygonomics.RequireRealmRole("admin"))

admin.GET("/users", func(c *gin.Context) {
	users, err := kc.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "keycloak unavailable"})
		return
	}
	c.JSON(http.StatusOK, users)
})

admin.PUT("/users/:id/roles/:role", func(c *gin.Context) {
	err := kc.AssignRealmRole(c.Request.Context(), c.Param("id"), c.Param("role"))
	switch {
	case err == nil:
		c.Status(http.StatusNoContent)
	case errors.Is(err, keygonomics.ErrRoleNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
	default:
		c.JSON(http.StatusBadGateway, gin.H{"error": "keycloak unavailable"})
	}
})
```

`RemoveRealmRole` has the same shape as `AssignRealmRole`.

### 8. Run and test it

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
KEYCLOAK_ISSUER=https://sso.example.com/realms/myrealm \
KEYCLOAK_CLIENT_ID=my-backend \
KEYCLOAK_CLIENT_SECRET=... \
go run ./examples/gin
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

### Client

#### `Client`

Verifies Keycloak tokens against a realm's JWKS and calls the Admin REST API. Safe for concurrent use. Create one at startup and share it; it caches the signing keys and refreshes them in the background, and caches the service-account token until shortly before it expires.

```go
var kc *keygonomics.Client // created once, used by every handler
```

#### `Config`

Everything `New` needs.

| Field | Required | Meaning |
| --- | --- | --- |
| `Issuer` | yes | Realm issuer URL, e.g. `https://sso.example.com/realms/myrealm`. The base URL and realm name are derived from it. |
| `ClientID`, `ClientSecret` | yes | Credentials of a confidential client with service accounts enabled (see [setup step 2](#2-create-a-client-for-your-service)). |
| `HTTPClient` | no | Used for Admin API and token requests. Defaults to `http.DefaultClient`. |
| `Keyfunc` | no | A [keyfunc](https://github.com/MicahParks/keyfunc) to verify signatures with instead of fetching the JWKS. For custom refresh intervals, several JWKS URLs, or a static key set in tests. |

#### `New(cfg Config) (*Client, error)`

The constructor. Fetches the JWKS immediately (unless `cfg.Keyfunc` is set) and fails if it cannot be reached.

```go
kc, err := keygonomics.New(keygonomics.Config{
	Issuer:       "https://sso.example.com/realms/myrealm",
	ClientID:     "my-backend",
	ClientSecret: secret,
})
if err != nil {
	log.Fatal(err) // bad issuer, or JWKS could not be fetched: realm down, TLS problem
}
```

#### `NewContext(ctx context.Context, cfg Config) (*Client, error)`

Same as `New`, but the background JWKS refresh goroutine stops when the context is cancelled. Use it if you shut the service down gracefully or create clients in tests.

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel() // stops the refresh goroutine

kc, err := keygonomics.NewContext(ctx, cfg)
```

Using a static key set in tests:

```go
kf, err := keyfunc.NewJWKSetJSON(jwksJSON)
if err != nil {
	log.Fatal(err)
}
kc, err := keygonomics.New(keygonomics.Config{
	Issuer: "https://sso.example.com/realms/test", ClientID: "x", ClientSecret: "y",
	Keyfunc: kf,
})
```

#### `JWKSURL(issuerURL string) string`

Pure helper that turns an issuer URL into the JWKS URL. Trailing slashes are stripped. `New` uses it internally.

```go
u := keygonomics.JWKSURL("https://sso.example.com/realms/myrealm/")
// "https://sso.example.com/realms/myrealm/protocol/openid-connect/certs"
```

### Verification

#### `(*Client).Verify(rawToken string) (*Claims, error)`

Parses a raw JWT, checks the signature against the JWKS, and validates `exp`, `nbf`, and `iat`. Returns the parsed claims or an error wrapping `ErrInvalidToken`.

```go
claims, err := kc.Verify(rawToken)
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

#### `ExtractBearerToken(header string) (string, error)`

Pulls the token out of an `Authorization` header value. The `Bearer` scheme is matched case-insensitively. Returns [ErrMissingBearerToken] for a missing header, another scheme (`Basic ...`), or an empty token.

```go
raw, err := keygonomics.ExtractBearerToken(r.Header.Get("Authorization"))
if err != nil {
	http.Error(w, "missing bearer token", http.StatusUnauthorized)
	return
}
```

#### `ErrMissingBearerToken`

Sentinel error returned by `ExtractBearerToken` when no bearer token could be found.

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

### Users and roles

These methods call the Keycloak Admin REST API as your service's own account. They need the realm-management roles described in [setup step 2](#2-create-a-client-for-your-service); a missing role shows up as a `403` wrapped in `ErrAdminRequestFailed`.

#### `(*Client).ListUsers(ctx context.Context) ([]User, error)`

Every user in the realm with the realm roles mapped directly to them. Pages through Keycloak internally; the returned slice is never `nil`.

```go
users, err := kc.ListUsers(ctx)
for _, u := range users {
	fmt.Println(u.ID, u.Username, u.Enabled, u.RealmRoles)
}
```

#### `(*Client).AssignRealmRole(ctx context.Context, userID, role string) error`

Grants a realm role to a user. `userID` is the Keycloak UUID (the same value as `claims.UUID()`); `role` is the role name. Idempotent: assigning a role the user already has is not an error. Returns an error wrapping `ErrRoleNotFound` if no such realm role exists.

```go
if err := kc.AssignRealmRole(ctx, userID, "editor"); err != nil {
	if errors.Is(err, keygonomics.ErrRoleNotFound) {
		// no realm role called "editor"
	}
}
```

#### `(*Client).RemoveRealmRole(ctx context.Context, userID, role string) error`

Revokes a realm role from a user. Same arguments and errors as `AssignRealmRole`. Removing a role the user does not have is not an error.

```go
err := kc.RemoveRealmRole(ctx, userID, "editor")
```

#### `User`

One entry from `ListUsers`.

| Field | JSON | Type |
| --- | --- | --- |
| `ID` | `id` | `string` — the Keycloak UUID |
| `Username` | `username` | `string` |
| `Email` | `email` | `string` |
| `Enabled` | `enabled` | `bool` |
| `RealmRoles` | `realm_roles` | `[]string`, never `nil` |

#### `ErrRoleNotFound`

Sentinel error wrapped by `AssignRealmRole` and `RemoveRealmRole` when the named realm role does not exist. Map it to `404` in your handlers.

#### `ErrAdminRequestFailed`

Sentinel error wrapped by every Admin API failure with a non-2xx status, including a rejected service-account login. The error message includes the status code and the start of Keycloak's response body.

```go
if errors.Is(err, keygonomics.ErrAdminRequestFailed) {
	log.Printf("keycloak admin api: %v", err) // e.g. "...: status 403: {"error":"unknown_error"}"
}
```

### Middleware and handler helpers

#### `RequireAuth(kc *keygonomics.Client) gin.HandlerFunc`

The authentication middleware. Reads the `Authorization` header, verifies the token, and stores the claims in the Gin context. Aborts with `401` and a JSON error body if anything is wrong. Attach it to a group so every route beneath it is protected.

```go
api := r.Group("/api", keygonomics.RequireAuth(kc))
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

#### `GetClaims(c *gin.Context) (*keygonomics.Claims, error)`

Returns the full claims stored by `RequireAuth`, or [ErrNoClaims] on routes where `RequireAuth` did not run. On protected routes the error can be safely discarded.

```go
func meHandler(c *gin.Context) {
	claims, _ := keygonomics.GetClaims(c)
	c.JSON(http.StatusOK, gin.H{
		"uuid":  claims.UUID(),
		"email": claims.Email,
	})
}
```

#### `GetUUID(c *gin.Context) (string, error)`

Shortcut for `GetClaims(c)` followed by `.UUID()`. Handy when all you need is the user ID.

```go
func createOrder(c *gin.Context) {
	userID, _ := keygonomics.GetUUID(c)
	order := db.CreateOrder(userID, ...)
	c.JSON(http.StatusCreated, order)
}
```

#### `GetRealmRoles(c *gin.Context) ([]string, error)`

Shortcut for `GetClaims(c)` followed by `.RealmRoles()`. The slice is never `nil` on success.

```go
roles, _ := keygonomics.GetRealmRoles(c)
c.JSON(http.StatusOK, gin.H{"roles": roles})
```

#### `ErrNoClaims`

Sentinel error returned by `GetClaims`, `GetUUID`, and `GetRealmRoles` when no verified claims are present in the context, meaning `RequireAuth` has not run for the request.

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
- `ListUsers`, `AssignRealmRole`, and `RemoveRealmRole` act with your service's permissions, not the caller's. Always put them behind `RequireAuth` plus a role check, and give the service account only `view-users` and `manage-users`, not `realm-admin`.

## License

Apache License 2.0. See [LICENSE](LICENSE).
