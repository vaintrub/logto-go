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
import logto "github.com/vaintrub/logto-go"

client, err := logto.New(
    "https://your-tenant.logto.app",
    "m2m-app-id",
    "m2m-app-secret",
    logto.WithResource("https://your-tenant.logto.app/api"),
)

// Get user
user, err := client.GetUser(ctx, "user-id")

// List organizations
orgs, err := client.ListOrganizations(ctx)
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
| `WithTimeout(d)` | HTTP timeout | 5s |
| `WithRetry(max, backoff)` | Retry config | 1, 500ms |
| `WithHTTPClient(c)` | Custom HTTP client | - |
| `WithLogger(l)` | slog.Logger | - |
| `WithResource(url)` | M2M resource | - |
| `WithScope(s)` | M2M scope | "all" |

## Error Handling

```go
if errors.Is(err, logto.ErrNotFound) {
    // handle 404
}
if errors.Is(err, logto.ErrRateLimited) {
    // handle 429
}
```

## License

MIT
