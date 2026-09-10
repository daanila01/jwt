package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// AlgorithmHS256 is the alg header value for HMAC with SHA-256.
const AlgorithmHS256 = "HS256"

// HS256 signs and verifies with HMAC-SHA-256. The key is symmetric, so the same
// value does both: anyone who can verify a token can also issue one. Use it only
// when the issuer and the verifier are the same service or the same trust
// boundary.
//
// It is safe for concurrent use.
type HS256 struct {
	key []byte
}

// NewHS256 returns a signer and verifier for the given secret. The key must be at
// least 32 bytes, the output size of SHA-256, which RFC 7518 requires. Generate it
// with crypto/rand; a password or a passphrase does not carry enough entropy.
//
// The returned value keeps the given slice rather than copying it. Do not modify
// or zero it afterwards, or the key changes underneath the signer.
func NewHS256(key []byte) (*HS256, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("%w: key must be at least 32 bytes", ErrKeyInvalid)
	}

	return &HS256{
		key: key,
	}, nil
}

// Algorithm returns [AlgorithmHS256].
func (h *HS256) Algorithm() string {
	return AlgorithmHS256
}

// Sign returns the HMAC-SHA-256 of signingInput.
func (h *HS256) Sign(signingInput []byte) ([]byte, error) {
	hsh := hmac.New(sha256.New, h.key)
	_, err := hsh.Write(signingInput)
	if err != nil {
		return nil, err
	}
	return hsh.Sum(nil), nil
}

// Verify recomputes the signature and compares it in constant time, returning
// [ErrSignatureInvalid] on a mismatch.
func (h *HS256) Verify(signingInput, signature []byte) error {
	expectedSignature, err := h.Sign(signingInput)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expectedSignature) {
		return ErrSignatureInvalid
	}
	return nil
}
