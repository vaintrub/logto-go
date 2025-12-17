package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Supported signature algorithms
var supportedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// TokenValidator validates JWT tokens and returns TokenInfo
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*TokenInfo, error)
}

// JWKSValidator validates JWT tokens using cached JWKS public keys
type JWKSValidator struct {
	jwksURL    string
	httpClient *http.Client
	issuer     string
	audience   string // Expected audience (API resource indicator)
	logger     *slog.Logger

	mu        sync.RWMutex
	keySet    *jose.JSONWebKeySet
	lastFetch time.Time
	cacheTTL  time.Duration
}

// NewJWKSValidator creates a new JWT validator with JWKS caching.
//
// Parameters:
//   - jwksURL: URL to fetch JWKS public keys from (e.g., "https://your-tenant.logto.app/oidc/jwks")
//   - issuer: Expected token issuer (e.g., "https://your-tenant.logto.app/oidc")
//   - audience: Expected audience - the API resource indicator the token was issued for.
//     This is critical for security: tokens issued for different APIs will be rejected.
//     Use empty string to skip audience validation (NOT recommended for production).
//   - cacheTTL: How long to cache JWKS keys before refreshing
//   - logger: Optional slog.Logger for debug output (nil uses slog.Default())
func NewJWKSValidator(jwksURL, issuer, audience string, cacheTTL time.Duration, logger *slog.Logger) (*JWKSValidator, error) {
	if jwksURL == "" {
		return nil, fmt.Errorf("%w: jwksURL is required", ErrInvalidConfig)
	}
	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrInvalidConfig)
	}
	if cacheTTL <= 0 {
		return nil, fmt.Errorf("%w: cacheTTL must be positive", ErrInvalidConfig)
	}

	if logger == nil {
		logger = slog.Default()
	}

	v := &JWKSValidator{
		jwksURL:    jwksURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		issuer:     issuer,
		audience:   audience,
		logger:     logger,
		cacheTTL:   cacheTTL,
	}

	return v, nil
}

// ValidateToken validates a JWT token and returns TokenInfo
func (v *JWKSValidator) ValidateToken(ctx context.Context, tokenString string) (*TokenInfo, error) {
	// Check if keys need refresh (fast path with read lock)
	v.mu.RLock()
	needsRefresh := v.keySet == nil || time.Since(v.lastFetch) > v.cacheTTL
	v.mu.RUnlock()

	if needsRefresh {
		// refreshKeys handles its own locking for cache update
		if err := v.refreshKeys(ctx); err != nil {
			// Check if we have cached keys to fall back to
			v.mu.RLock()
			hasKeys := v.keySet != nil
			v.mu.RUnlock()

			if !hasKeys {
				return nil, fmt.Errorf("%w: %w", ErrJWKSFetchFailed, err)
			}
			// Continue with cached keys on refresh failure
			v.logger.WarnContext(ctx, "JWKS refresh failed, using cached keys", slog.Any("error", err))
		}
	}

	// Parse the signed JWT
	tok, err := jose.ParseSigned(tokenString, supportedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get key ID from header
	if len(tok.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures in token")
	}
	kid := tok.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, fmt.Errorf("kid not found in token header")
	}

	// Find the key in the cached JWKS
	v.mu.RLock()
	keys := v.keySet.Key(kid)
	v.mu.RUnlock()

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w for kid: %s", ErrKeyNotFound, kid)
	}

	// Verify signature and get payload
	payload, err := tok.Verify(keys[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	// Parse claims from payload
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Parse raw claims for custom claim access
	var rawClaims map[string]any
	if err := json.Unmarshal(payload, &rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse raw claims: %w", err)
	}

	// Validate issuer
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, v.issuer, claims.Issuer)
	}

	// Validate audience (critical security check)
	// The audience claim identifies the API resource the token was issued for.
	// See: https://auth-wiki.logto.io/access-token
	if v.audience != "" {
		if !claims.HasAudience(v.audience) {
			return nil, fmt.Errorf("%w: token not issued for %s", ErrInvalidAudience, v.audience)
		}
	}

	// Validate not before (nbf)
	if claims.NotBefore != nil && time.Now().Unix() < claims.NotBefore.Unix() {
		return nil, ErrTokenNotYetValid
	}

	// Validate expiration
	if claims.ExpiresAt != nil && time.Now().Unix() > claims.ExpiresAt.Unix() {
		return nil, ErrTokenExpired
	}

	// Convert Claims to TokenInfo with all JWT fields
	return &TokenInfo{
		// Standard JWT claims
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		NotBefore: claims.NotBefore,
		JWTID:     claims.ID,

		// Logto-specific claims
		ClientID:       claims.ClientID,
		OrganizationID: claims.OrganizationID,
		Scopes:         claims.GetScopes(),

		// Convenience alias (backward compatibility)
		UserID: claims.Subject,

		// Raw claims for custom claim access
		RawClaims: rawClaims,
	}, nil
}

// refreshKeys fetches the latest JWKS and updates the cache
func (v *JWKSValidator) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Update cache
	v.mu.Lock()
	v.keySet = &keySet
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

// StartBackgroundRefresh starts a goroutine to refresh JWKS periodically.
// The ctx parameter controls the lifecycle of the background goroutine - when ctx is cancelled,
// the background refresh stops. Each refresh operation uses a fresh context with 30s timeout.
func (v *JWKSValidator) StartBackgroundRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Use a fresh context with timeout for each refresh operation
				// This ensures refresh works even if the parent ctx has a short deadline
				refreshCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := v.refreshKeys(refreshCtx); err != nil {
					v.logger.Warn("Background JWKS refresh failed", slog.Any("error", err))
				}
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()
}
