package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
)

// The alg header values for ECDSA, as registered by RFC 7518.
//
// Unlike the HMAC names, the number here fixes two things at once: the curve and
// the hash. ES256 is P-256 with SHA-256 and nothing else.
//
// ES512 is the one to watch. Its curve is P-521, not P-512: the field is 521
// bits wide, which is not a multiple of eight, so each coordinate occupies 66
// bytes and a signature is 132 rather than 128.
const (
	AlgorithmES256 = "ES256"
	AlgorithmES384 = "ES384"
	AlgorithmES512 = "ES512"
)

// ECDSASigner signs with an elliptic-curve private key.
//
// Signing and verifying take different keys, so this type and [ECDSAVerifier]
// are separate: a service that only checks tokens cannot issue one.
//
// The signature is not deterministic. Each call draws a random nonce, so two
// signatures over the same input differ, and a reference vector can only be
// verified rather than reproduced. That nonce is also the algorithm's weak
// point: a repeated or predictable one exposes the private key, which is how
// the PlayStation 3 was broken. Go draws it from crypto/rand.
//
// It is safe for concurrent use.
type ECDSASigner struct {
	algorithm string
	newHash   func() hash.Hash
	curve     elliptic.Curve
	key       *ecdsa.PrivateKey
}

// ECDSAVerifier checks elliptic-curve signatures with a public key.
//
// It is safe for concurrent use.
type ECDSAVerifier struct {
	algorithm string
	newHash   func() hash.Hash
	curve     elliptic.Curve
	key       *ecdsa.PublicKey
}

// coordinateSize is how many bytes one half of a signature takes: the width of
// the curve's field, rounded up. JOSE pads each half to exactly this, which is
// what makes the signature a fixed length.
func coordinateSize(c elliptic.Curve) int {
	return (c.Params().BitSize + 7) / 8
}

func newECDSASigner(algorithm string, newHash func() hash.Hash, curve elliptic.Curve, key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: key is nil", ErrKeyInvalid)
	}
	if key.Curve != curve {
		return nil, fmt.Errorf("%w: %s needs a key on %s, got %s", ErrKeyInvalid, algorithm, curve.Params().Name, curveName(key.Curve))
	}

	return &ECDSASigner{algorithm: algorithm, newHash: newHash, curve: curve, key: key}, nil
}

func newECDSAVerifier(algorithm string, newHash func() hash.Hash, curve elliptic.Curve, key *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: key is nil", ErrKeyInvalid)
	}
	if key.Curve != curve {
		return nil, fmt.Errorf("%w: %s needs a key on %s, got %s", ErrKeyInvalid, algorithm, curve.Params().Name, curveName(key.Curve))
	}

	return &ECDSAVerifier{algorithm: algorithm, newHash: newHash, curve: curve, key: key}, nil
}

// curveName is only for error messages, where a nil curve must not panic.
func curveName(c elliptic.Curve) string {
	if c == nil {
		return "no curve"
	}
	return c.Params().Name
}

// NewES256Signer returns a signer for ECDSA on P-256 with SHA-256. The key's
// curve must be P-256: a key on another curve is refused rather than quietly
// producing signatures nobody expects.
func NewES256Signer(key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	return newECDSASigner(AlgorithmES256, sha256.New, elliptic.P256(), key)
}

// NewES384Signer returns a signer for ECDSA on P-384 with SHA-384.
func NewES384Signer(key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	return newECDSASigner(AlgorithmES384, sha512.New384, elliptic.P384(), key)
}

// NewES512Signer returns a signer for ECDSA on P-521 with SHA-512. The curve is
// P-521, despite the name.
func NewES512Signer(key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	return newECDSASigner(AlgorithmES512, sha512.New, elliptic.P521(), key)
}

// NewES256Verifier returns a verifier for ECDSA on P-256 with SHA-256.
func NewES256Verifier(key *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return newECDSAVerifier(AlgorithmES256, sha256.New, elliptic.P256(), key)
}

// NewES384Verifier returns a verifier for ECDSA on P-384 with SHA-384.
func NewES384Verifier(key *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return newECDSAVerifier(AlgorithmES384, sha512.New384, elliptic.P384(), key)
}

// NewES512Verifier returns a verifier for ECDSA on P-521 with SHA-512.
func NewES512Verifier(key *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return newECDSAVerifier(AlgorithmES512, sha512.New, elliptic.P521(), key)
}

// Algorithm returns the alg value this signer was built for.
func (s *ECDSASigner) Algorithm() string {
	return s.algorithm
}

// Sign hashes signingInput and returns the signature as JOSE wants it: the two
// halves of the result, each padded on the left with zeroes to the width of the
// curve, one after the other.
//
// The standard library's SignASN1 would wrap the same pair in ASN.1 DER, whose
// length varies from call to call. JOSE needs a fixed length, so this uses the
// lower-level Sign, which hands back the two numbers directly and leaves no DER
// to unwrap.
func (s *ECDSASigner) Sign(signingInput []byte) ([]byte, error) {
	h := s.newHash()
	h.Write(signingInput)

	r, v, err := ecdsa.Sign(rand.Reader, s.key, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("ecdsa: %w", err)
	}

	size := coordinateSize(s.curve)
	signature := make([]byte, 2*size)
	r.FillBytes(signature[:size])
	v.FillBytes(signature[size:])

	return signature, nil
}

// Algorithm returns the alg value this verifier accepts.
func (v *ECDSAVerifier) Algorithm() string {
	return v.algorithm
}

// Verify splits the signature into its two halves and checks them against the
// public key, returning [ErrSignatureInvalid] when they do not match.
//
// The length is checked first. Splitting a signature of the wrong size in half
// would produce two numbers that mean nothing, and the check that followed
// would fail for a reason that has nothing to do with the signature.
func (v *ECDSAVerifier) Verify(signingInput, signature []byte) error {
	size := coordinateSize(v.curve)
	if len(signature) != 2*size {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrSignatureInvalid, len(signature), 2*size)
	}

	h := v.newHash()
	h.Write(signingInput)

	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])

	if !ecdsa.Verify(v.key, h.Sum(nil), r, s) {
		return ErrSignatureInvalid
	}

	return nil
}
