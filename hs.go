package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// The alg header values for HMAC, as registered by RFC 7518. The number names
// the hash, not the key length: HS256 is HMAC with SHA-256.
const (
	AlgorithmHS256 = "HS256"
	AlgorithmHS384 = "HS384"
	AlgorithmHS512 = "HS512"
)

// HMAC signs and verifies with a keyed hash. One type covers HS256, HS384 and
// HS512, which differ only in the hash they use; pick one with the matching
// constructor.
//
// The key is symmetric, so the same value does both: anyone who can verify a
// token can also issue one. Use it when the issuer and the verifier are the
// same service or sit inside one trust boundary, and reach for an asymmetric
// algorithm when they do not.
//
// It is safe for concurrent use.
type HMAC struct {
	algorithm string
	newHash   func() hash.Hash
	key       []byte
}

// newHMAC checks the key against the hash it will be used with and builds the
// signer. The minimum comes from the hash itself rather than a written-down
// number, so the three constructors cannot disagree with the algorithm they
// name.
func newHMAC(algorithm string, newHash func() hash.Hash, key []byte) (*HMAC, error) {
	hashSize := newHash().Size()
	if len(key) < hashSize {
		return nil, fmt.Errorf("%w: key must be at least %d bytes", ErrKeyInvalid, hashSize)
	}

	return &HMAC{
		algorithm: algorithm,
		newHash:   newHash,
		key:       key,
	}, nil
}

// NewHS256 returns a signer and verifier for HMAC with SHA-256. The key must be
// at least 32 bytes, the size of the hash output, which RFC 7518 requires.
// Generate it with crypto/rand: a password or a passphrase does not carry
// enough entropy, and a hex string carries half of what its length suggests.
//
// The returned value keeps the given slice rather than copying it. Do not
// modify or wipe it afterwards, or the key changes underneath the signer.
func NewHS256(key []byte) (*HMAC, error) {
	return newHMAC(AlgorithmHS256, sha256.New, key)
}

// NewHS384 returns a signer and verifier for HMAC with SHA-384. The key must be
// at least 48 bytes. See [NewHS256] for how the key is treated.
func NewHS384(key []byte) (*HMAC, error) {
	return newHMAC(AlgorithmHS384, sha512.New384, key)
}

// NewHS512 returns a signer and verifier for HMAC with SHA-512. The key must be
// at least 64 bytes. See [NewHS256] for how the key is treated.
func NewHS512(key []byte) (*HMAC, error) {
	return newHMAC(AlgorithmHS512, sha512.New, key)
}

// Algorithm returns the alg value this signer was built for: [AlgorithmHS256],
// [AlgorithmHS384] or [AlgorithmHS512].
func (h *HMAC) Algorithm() string {
	return h.algorithm
}

// Sign returns the keyed hash of signingInput. The hash is built inside the
// call rather than kept on the struct, because a hash.Hash carries state and
// sharing one across goroutines would corrupt signatures without any race the
// detector could see.
func (h *HMAC) Sign(signingInput []byte) ([]byte, error) {
	hsh := hmac.New(h.newHash, h.key)
	_, err := hsh.Write(signingInput)
	if err != nil {
		return nil, err
	}
	return hsh.Sum(nil), nil
}

// Verify recomputes the signature and compares it in constant time, returning
// [ErrSignatureInvalid] on a mismatch.
func (h *HMAC) Verify(signingInput, signature []byte) error {
	expectedSignature, err := h.Sign(signingInput)
	if err != nil {
		return err
	}
	if !hmac.Equal(signature, expectedSignature) {
		return ErrSignatureInvalid
	}
	return nil
}
