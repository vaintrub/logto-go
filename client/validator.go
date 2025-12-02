package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator validates JWT tokens and returns TokenInfo
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*TokenInfo, error)
}

// JWKSValidator validates JWT tokens using cached JWKS public keys
type JWKSValidator struct {
	jwksURL    string
	httpClient *http.Client
	issuer     string
	logger     *slog.Logger

	mu        sync.RWMutex
	rsaKeys   map[string]*rsa.PublicKey   // kid -> RSA public key
	ecKeys    map[string]*ecdsa.PublicKey // kid -> EC public key
	lastFetch time.Time
	cacheTTL  time.Duration
}

// NewJWKSValidator creates a new JWT validator with JWKS caching
func NewJWKSValidator(jwksURL, issuer string, cacheTTL time.Duration, logger *slog.Logger) (*JWKSValidator, error) {
	if logger == nil {
		logger = slog.Default()
	}

	v := &JWKSValidator{
		jwksURL:    jwksURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		issuer:     issuer,
		logger:     logger,
		rsaKeys:    make(map[string]*rsa.PublicKey),
		ecKeys:     make(map[string]*ecdsa.PublicKey),
		cacheTTL:   cacheTTL,
	}

	// Initial fetch
	if err := v.refreshKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("initial JWKS fetch failed: %w", err)
	}

	return v, nil
}

// ValidateToken validates a JWT token and returns TokenInfo
func (v *JWKSValidator) ValidateToken(ctx context.Context, tokenString string) (*TokenInfo, error) {
	// Check if keys need refresh
	v.mu.RLock()
	needsRefresh := time.Since(v.lastFetch) > v.cacheTTL
	v.mu.RUnlock()

	if needsRefresh {
		if err := v.refreshKeys(ctx); err != nil {
			// Continue with cached keys on refresh failure
			v.logger.WarnContext(ctx, "JWKS refresh failed, using cached keys", slog.Any("error", err))
		}
	}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		v.mu.RLock()
		defer v.mu.RUnlock()

		// Check signing method and return appropriate key
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			key, exists := v.rsaKeys[kid]
			if !exists {
				return nil, fmt.Errorf("RSA public key not found for kid: %s", kid)
			}
			return key, nil
		case *jwt.SigningMethodECDSA:
			key, exists := v.ecKeys[kid]
			if !exists {
				return nil, fmt.Errorf("EC public key not found for kid: %s", kid)
			}
			return key, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		return nil, fmt.Errorf("token parse failed: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
	}

	// Validate expiration
	if time.Now().Unix() > claims.ExpiresAt.Unix() {
		return nil, fmt.Errorf("token expired")
	}

	// Convert Claims to TokenInfo
	return &TokenInfo{
		UserID:         claims.Subject,
		OrganizationID: claims.OrganizationID,
		Scopes:         claims.GetScopes(),
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

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			// RSA fields
			N string `json:"n"`
			E string `json:"e"`
			// EC fields
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}

	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}

	newRSAKeys := make(map[string]*rsa.PublicKey)
	newECKeys := make(map[string]*ecdsa.PublicKey)

	for _, key := range jwks.Keys {
		switch key.Kty {
		case "RSA":
			publicKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				v.logger.Warn("Failed to parse RSA key", slog.String("kid", key.Kid), slog.Any("error", err))
				continue
			}
			newRSAKeys[key.Kid] = publicKey
		case "EC":
			publicKey, err := parseECPublicKey(key.Crv, key.X, key.Y)
			if err != nil {
				v.logger.Warn("Failed to parse EC key", slog.String("kid", key.Kid), slog.Any("error", err))
				continue
			}
			newECKeys[key.Kid] = publicKey
		}
	}

	// Update cache
	v.mu.Lock()
	v.rsaKeys = newRSAKeys
	v.ecKeys = newECKeys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

// parseECPublicKey parses an EC public key from JWK crv, x, and y parameters
func parseECPublicKey(crv, x, y string) (*ecdsa.PublicKey, error) {
	// Determine curve
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	// Decode base64url-encoded X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	// Decode base64url-encoded Y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	// Construct EC public key
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return pubKey, nil
}

// parseRSAPublicKey parses an RSA public key from JWK n and e parameters
func parseRSAPublicKey(n, e string) (*rsa.PublicKey, error) {
	// Decode base64url-encoded modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode base64url-encoded exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var exponent int
	for _, b := range eBytes {
		exponent = exponent<<8 + int(b)
	}

	// Construct RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: exponent,
	}

	return pubKey, nil
}

// StartBackgroundRefresh starts a goroutine to refresh JWKS periodically
func (v *JWKSValidator) StartBackgroundRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := v.refreshKeys(ctx); err != nil {
					v.logger.WarnContext(ctx, "Background JWKS refresh failed", slog.Any("error", err))
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
