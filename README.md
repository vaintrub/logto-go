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

    logto "github.com/vaintrub/logto-go"
)

c, err := logto.NewClient(
    "https://your-tenant.logto.app",
    "m2m-app-id",
    "m2m-app-secret",
    logto.WithResource("https://your-tenant.logto.app/api"),
)

ctx := context.Background()

// Get user
user, err := c.GetUser(ctx, "user-id")

// Create user
newUser, err := c.CreateUser(ctx, logto.UserCreate{
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
- HTTP connection pooling with optimized defaults

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `logto.WithTimeout(d)` | HTTP client timeout | 5s |
| `logto.WithHTTPClient(c)` | Custom HTTP client (overrides timeout) | - |
| `logto.WithResource(url)` | M2M resource URL | - |
| `logto.WithScope(s)` | M2M scope | "all" |

## Error Handling

```go
import logto "github.com/vaintrub/logto-go"

if errors.Is(err, logto.ErrNotFound) {
    // handle 404
}
if errors.Is(err, logto.ErrRateLimited) {
    // handle 429
}
if errors.Is(err, logto.ErrUserNotFound) {
    // user not found in search results
    // also matches ErrNotFound
}
```

## Pagination with Iterators

```go
iter := c.ListUsersIter(100) // page size
for iter.Next(ctx) {
    user := iter.User()
    fmt.Println(user.ID, user.Username)
}
if err := iter.Err(); err != nil {
    // handle error
}

// Or collect all at once
users, err := c.ListUsersIter(100).Collect(ctx)
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
