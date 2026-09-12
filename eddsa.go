package jwt

import (
	"crypto/ed25519"
	"fmt"
)

// AlgorithmEdDSA is the alg header value for Edwards-curve signatures, as
// registered by RFC 8037.
//
// It names the scheme, not the curve: RFC 8032 defines EdDSA over both Ed25519
// and Ed448, and a key says which one it is. This package implements Ed25519,
// the only one the standard library provides.
const AlgorithmEdDSA = "EdDSA"

// EdDSASigner signs with an Ed25519 private key.
//
// Signing and verifying take different keys here, unlike HMAC, which is why
// this type and [EdDSAVerifier] are separate: a service that only checks tokens
// holds a verifier and has no way to issue one.
//
// The signature is deterministic. The same key over the same input always
// produces the same bytes, because the nonce is derived from them rather than
// drawn at random. That removes the failure that broke the PlayStation 3, where
// a repeated nonce exposed the private key.
//
// It is safe for concurrent use.
type EdDSASigner struct {
	key ed25519.PrivateKey
}

// NewEdDSASigner returns a signer for the given private key, which must be
// exactly ed25519.PrivateKeySize bytes. The type is a plain byte slice and the
// standard library panics on a wrong length, so the check belongs here, once,
// rather than on the first request.
//
// Build the key with ed25519.GenerateKey or ed25519.NewKeyFromSeed. The
// returned value keeps the slice rather than copying it: do not modify or wipe
// it afterwards.
func NewEdDSASigner(key ed25519.PrivateKey) (*EdDSASigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: key length must be equal to %d bytes", ErrKeyInvalid, ed25519.PrivateKeySize)
	}
	return &EdDSASigner{key: key}, nil
}

// Sign returns the 64-byte signature over signingInput. The error is always
// nil; it is in the signature because [Signer] must accommodate algorithms that
// can fail, which RSA does.
func (s *EdDSASigner) Sign(signingInput []byte) ([]byte, error) {
	return ed25519.Sign(s.key, signingInput), nil
}

// Algorithm returns [AlgorithmEdDSA].
func (s *EdDSASigner) Algorithm() string {
	return AlgorithmEdDSA
}

// EdDSAVerifier checks Ed25519 signatures with a public key. It cannot sign,
// which is the point of it being a separate type from [EdDSASigner].
//
// It is safe for concurrent use.
type EdDSAVerifier struct {
	key ed25519.PublicKey
}

// NewEdDSAVerifier returns a verifier for the given public key, which must be
// exactly ed25519.PublicKeySize bytes. As with the signer, the standard library
// panics on a wrong length, so the length is checked here.
func NewEdDSAVerifier(key ed25519.PublicKey) (*EdDSAVerifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: key length must be equal to %d bytes", ErrKeyInvalid, ed25519.PublicKeySize)
	}
	return &EdDSAVerifier{key: key}, nil
}

// Verify reports whether signature is valid for signingInput under this key,
// returning [ErrSignatureInvalid] when it is not.
func (v *EdDSAVerifier) Verify(signingInput, signature []byte) error {
	if !ed25519.Verify(v.key, signingInput, signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// Algorithm returns [AlgorithmEdDSA].
func (v *EdDSAVerifier) Algorithm() string {
	return AlgorithmEdDSA
}
