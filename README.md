# keygonomics

[![CI](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml/badge.svg)](https://github.com/mobn0/keygonomics/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mobn0/keygonomics.svg)](https://pkg.go.dev/github.com/mobn0/keygonomics)

Keycloak JWT verification for Go, with ready-made [Gin](https://github.com/gin-gonic/gin) middleware.

If your Go service sits behind Keycloak, every request arrives with a bearer token and you need to answer three questions before doing anything else:

1. Is this token genuine and still valid?
2. Who is the user? (Keycloak's user ID is the token's `sub` claim, a UUID.)
3. What roles do they have, so I can allow or deny this route?

`keygonomics` answers all three in a few lines. It fetches and caches your realm's public keys (JWKS), verifies the token signature and expiry, and hands you a typed `Claims` struct with helpers for the user UUID and for realm and client roles.

The package is split in two:

| Package | Import path | Purpose |
| --- | --- | --- |
| `keygonomics` | `github.com/mobn0/keygonomics` | Framework-agnostic core: JWKS caching, verification, claims parsing. |
| `keygin` | `github.com/mobn0/keygonomics/gin` | Gin middleware and context helpers built on the core. |

The core has no dependency on Gin, so it can be used with `net/http` or any other router. More adapters may follow.

## Installation

```sh
go get github.com/mobn0/keygonomics
```

The Gin adapter lives in the same module, so the command above installs both. Requires Go 1.27 or newer.

## Quick start

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/mobn0/keygonomics"
	keygin "github.com/mobn0/keygonomics/gin"
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
	api := r.Group("/api", keygin.RequireAuth(verifier))

	// 3. Read the user's identity inside a handler.
	api.GET("/me", func(c *gin.Context) {
		claims, _ := keygin.GetClaims(c)
		c.JSON(http.StatusOK, gin.H{
			"uuid":     claims.UUID(),
			"username": claims.PreferredUsername,
			"roles":    claims.RealmRoles(),
		})
	})

	// 4. Restrict a route to a realm role...
	api.GET("/admin", keygin.RequireRealmRole("admin"), func(c *gin.Context) {
		uuid, _ := keygin.GetUUID(c)
		c.JSON(http.StatusOK, gin.H{"admin": uuid})
	})

	// ...or to a role defined on a specific client.
	api.GET("/reports", keygin.RequireClientRole("reporting-api", "reports:read"), func(c *gin.Context) {
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

## Realm roles vs. client roles

Keycloak has two kinds of roles, and they show up in different places in the token. This trips up almost everyone at least once.

**Realm roles** are defined at the realm level (Realm settings → Realm roles) and apply across every client in the realm. They appear in the token under `realm_access`:

```json
"realm_access": { "roles": ["admin", "offline_access", "uma_authorization"] }
```

Check them with `claims.HasRealmRole("admin")` or `keygin.RequireRealmRole("admin")`.

**Client roles** are defined on a specific client (Clients → *your client* → Roles) and are scoped to that client. They appear under `resource_access`, keyed by the client ID:

```json
"resource_access": {
  "reporting-api": { "roles": ["reports:read"] },
  "account":       { "roles": ["manage-account", "view-profile"] }
}
```

Check them with `claims.HasClientRole("reporting-api", "reports:read")` or `keygin.RequireClientRole("reporting-api", "reports:read")`. The first argument is the **client ID** as shown in the Keycloak admin console, not the client's display name or its internal UUID.

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
