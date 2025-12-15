package validator

import "errors"

// Sentinel errors for use with errors.Is()
var (
	// ErrInvalidConfig indicates invalid validator configuration.
	ErrInvalidConfig = errors.New("invalid validator configuration")

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidIssuer indicates the token issuer doesn't match expected value.
	ErrInvalidIssuer = errors.New("invalid issuer")

	// ErrInvalidAudience indicates the token audience doesn't match expected value.
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrTokenNotYetValid indicates the token is not yet valid (nbf claim).
	ErrTokenNotYetValid = errors.New("token not yet valid")

	// ErrInvalidSignature indicates the token signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrKeyNotFound indicates the public key for the token was not found.
	ErrKeyNotFound = errors.New("public key not found")

	// ErrJWKSFetchFailed indicates JWKS fetch from the endpoint failed.
	ErrJWKSFetchFailed = errors.New("JWKS fetch failed")
)
