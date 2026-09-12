package jwt

import (
	"encoding/base64"
	"fmt"
)

// SignOptions configures a call to [Sign]. It carries nothing yet: the header
// is a map the caller fills in, and the claims are the caller's own value, so
// there is nothing left for an option to reach.
//
// It exists so that a setting can be added later without changing the signature
// of [Sign], which is why the parameter is variadic. Passing none is normal.
type SignOptions struct{}

// Sign encodes and signs a token, returning it in compact serialization,
// base64url(header).base64url(claims).base64url(signature).
//
// The alg header parameter is written from signer and overwrites whatever h
// holds, so a token can never claim an algorithm other than the one that signed
// it. Nothing else in the header is touched: typ, kid and anything of your own
// are yours to set, and Sign writes them through unchanged.
//
// Claims are marshalled as they are. Sign fills nothing in, so a token expires
// only if you put an exp in it; [RegisteredClaims] carries the registered
// fields and setters that take a time.Time, if you want them.
//
// Pass nil for h when the header needs nothing beyond alg. Note that Sign
// writes into the map you give it rather than a copy.
func Sign(h map[string]any, c any, signer Signer, options ...SignOptions) (string, error) {
	if h == nil {
		h = make(map[string]any)
	}
	if isNil(c) {
		return "", fmt.Errorf("%w: claims is nil", ErrArgumentInvalid)
	}
	if signer == nil {
		return "", fmt.Errorf("%w: signer is nil", ErrArgumentInvalid)
	}

	h[headerAlgorithm] = signer.Algorithm()

	hEnc, err := marshalBase64(h)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	cEnc, err := marshalBase64(c)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	signingInput := hEnc + "." + cEnc
	s, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(s), nil
}
