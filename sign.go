package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// SignOptions configures a call to [Sign]. The zero value is valid and sets no
// time claims at all.
type SignOptions struct {
	// NotBefore sets the nbf claim. The zero value leaves it unset.
	NotBefore time.Time

	// Expiration sets the exp claim. The zero value leaves it unset, which means
	// a token that never expires; pass a value unless you are certain that is
	// what you want.
	Expiration time.Time

	// IssuedAt sets the iat claim. The zero value leaves it unset.
	IssuedAt time.Time
}

// Sign encodes and signs a token, returning it in compact serialization,
// base64url(header).base64url(claims).base64url(signature).
//
// The typ and alg header parameters are written from signer and overwrite
// whatever h holds, so a token can never claim an algorithm other than the one
// that signed it. Time claims named in opts are written into c.
//
// Pass nil for h when the header needs nothing beyond those two parameters. Only
// a literal nil: a nil pointer stored in an interface is not nil and will panic.
func Sign(h headers, c claims, signer Signer, opts SignOptions) (string, error) {
	if h == nil {
		h = &RegisteredHeaders{}
	}
	if isNil(h) || h.registeredHeaders() == nil {
		return "", fmt.Errorf("%w: headers is nil", ErrArgumentInvalid)
	}
	if isNil(c) || c.registeredClaims() == nil {
		return "", fmt.Errorf("%w: claims is nil", ErrArgumentInvalid)
	}
	if signer == nil {
		return "", fmt.Errorf("%w: signer is nil", ErrArgumentInvalid)
	}

	setRegisteredHeaders(h, signer)
	setRegisteredClaims(c, opts)

	hEnc, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	cEnc, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hEnc) + "." + base64.RawURLEncoding.EncodeToString(cEnc)
	s, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(s), nil
}

func setRegisteredHeaders(h headers, signer Signer) {
	hd := h.registeredHeaders()
	hd.Type = headerTypeJWT
	hd.Algorithm = signer.Algorithm()
}

func setRegisteredClaims(c claims, opts SignOptions) {
	if !opts.NotBefore.IsZero() {
		c.registeredClaims().NotBefore = opts.NotBefore.Unix()
	}
	if !opts.Expiration.IsZero() {
		c.registeredClaims().Expiration = opts.Expiration.Unix()
	}
	if !opts.IssuedAt.IsZero() {
		c.registeredClaims().IssuedAt = opts.IssuedAt.Unix()
	}
}
