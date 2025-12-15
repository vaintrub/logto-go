# logto-go

Go client for [Logto](https://logto.io) Management API.

> **Note**: This is a Management API client for server-side operations.
> For user authentication, use the [official Logto Go SDK](https://github.com/logto-io/go).

## Installation

```bash
go get github.com/vaintrub/logto-go
```

## Quick Start

```go
import (
    "context"

    "github.com/vaintrub/logto-go/client"
    "github.com/vaintrub/logto-go/models"
)

c, err := client.New(
    "https://your-tenant.logto.app",
    "m2m-app-id",
    "m2m-app-secret",
    client.WithResource("https://your-tenant.logto.app/api"),
)

ctx := context.Background()

// Get user
user, err := c.GetUser(ctx, "user-id")

// Create user
newUser, err := c.CreateUser(ctx, models.UserCreate{
    Username: "john",
    Password: "SecurePass123!",
})

// List organizations
orgs, err := c.ListOrganizations(ctx)
```

## Features

- M2M Authentication with automatic token caching
- Users, Organizations, Roles, Scopes CRUD
- Organization invitations
- JWT validation with JWKS
- Pagination iterators
- Retry with exponential backoff

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `client.WithTimeout(d)` | HTTP client timeout | 5s |
| `client.WithHTTPClient(c)` | Custom HTTP client (overrides timeout) | - |
| `client.WithLogger(l)` | slog.Logger for debug output | - |
| `client.WithResource(url)` | M2M resource URL | - |
| `client.WithScope(s)` | M2M scope | "all" |

## Error Handling

```go
import "github.com/vaintrub/logto-go/client"

if errors.Is(err, client.ErrNotFound) {
    // handle 404
}
if errors.Is(err, client.ErrRateLimited) {
    // handle 429
}
```

## JWT Validation

```go
import (
    "time"

    "github.com/vaintrub/logto-go/validator"
)

v, err := validator.NewJWKSValidator(
    "https://your-tenant.logto.app/oidc/jwks",
    "https://your-tenant.logto.app/oidc",
    "https://api.example.com", // audience
    time.Hour,                 // JWKS cache TTL
    nil,                       // optional logger
)

tokenInfo, err := v.ValidateToken(ctx, bearerToken)
userID := tokenInfo.GetUserID()
orgID := tokenInfo.GetOrganizationID()

if tokenInfo.HasScope("read:users") {
    // allowed
}
```

## License

MIT
