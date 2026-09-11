package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
)

// The alg header values for RSA, as registered by RFC 7518.
//
// Two families share one set of keys. RS is RSASSA-PKCS1-v1_5, the older
// padding, and its signatures are deterministic. PS is RSASSA-PSS, which mixes
// in a random salt, so its signatures differ from call to call and cannot be
// reproduced from a reference vector.
//
// PSS is the better construction and the one to pick for new systems; RS exists
// because most of the world already speaks it. Note that the same PKCS#1 v1.5
// padding is broken for *encryption* and fine for signing: they are different
// operations under one name.
const (
	AlgorithmRS256 = "RS256"
	AlgorithmRS384 = "RS384"
	AlgorithmRS512 = "RS512"

	AlgorithmPS256 = "PS256"
	AlgorithmPS384 = "PS384"
	AlgorithmPS512 = "PS512"
)

// MinRSAKeyBits is the smallest modulus this package accepts. Anything shorter
// is refused when the signer is built: RSA-1024 is within reach of a determined
// attacker and RSA-512 falls to a laptop.
const MinRSAKeyBits = 2048

// RSASigner signs with an RSA private key, under either padding scheme.
//
// Signing is by far the slowest operation in this package, on the order of a
// millisecond, while verification is among the fastest. That asymmetry is why
// RSA survives: one service issues tokens rarely and many verify them often.
//
// It is safe for concurrent use.
type RSASigner struct {
	algorithm string
	hash      crypto.Hash
	pss       bool
	key       *rsa.PrivateKey
}

// RSAVerifier checks RSA signatures with a public key.
//
// It is safe for concurrent use.
type RSAVerifier struct {
	algorithm string
	hash      crypto.Hash
	pss       bool
	key       *rsa.PublicKey
}

// pssOptions fixes the salt length to the size of the hash, which is what
// RFC 7518 requires of PS256, PS384 and PS512.
func pssOptions(h crypto.Hash) *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
}

func newRSASigner(algorithm string, h crypto.Hash, pss bool, key *rsa.PrivateKey) (*RSASigner, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: key is nil", ErrKeyInvalid)
	}
	if key.N == nil {
		return nil, fmt.Errorf("%w: key has no modulus", ErrKeyInvalid)
	}
	if bits := key.N.BitLen(); bits < MinRSAKeyBits {
		return nil, fmt.Errorf("%w: modulus is %d bits, want at least %d", ErrKeyInvalid, bits, MinRSAKeyBits)
	}

	return &RSASigner{algorithm: algorithm, hash: h, pss: pss, key: key}, nil
}

func newRSAVerifier(algorithm string, h crypto.Hash, pss bool, key *rsa.PublicKey) (*RSAVerifier, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: key is nil", ErrKeyInvalid)
	}
	if key.N == nil {
		return nil, fmt.Errorf("%w: key has no modulus", ErrKeyInvalid)
	}
	if bits := key.N.BitLen(); bits < MinRSAKeyBits {
		return nil, fmt.Errorf("%w: modulus is %d bits, want at least %d", ErrKeyInvalid, bits, MinRSAKeyBits)
	}

	return &RSAVerifier{algorithm: algorithm, hash: h, pss: pss, key: key}, nil
}

// NewRS256Signer returns a signer for RSASSA-PKCS1-v1_5 with SHA-256. The key's
// modulus must be at least [MinRSAKeyBits] bits.
func NewRS256Signer(key *rsa.PrivateKey) (*RSASigner, error) {
	return newRSASigner(AlgorithmRS256, crypto.SHA256, false, key)
}

// NewRS384Signer returns a signer for RSASSA-PKCS1-v1_5 with SHA-384.
func NewRS384Signer(key *rsa.PrivateKey) (*RSASigner, error) {
	return newRSASigner(AlgorithmRS384, crypto.SHA384, false, key)
}

// NewRS512Signer returns a signer for RSASSA-PKCS1-v1_5 with SHA-512.
func NewRS512Signer(key *rsa.PrivateKey) (*RSASigner, error) {
	return newRSASigner(AlgorithmRS512, crypto.SHA512, false, key)
}

// NewPS256Signer returns a signer for RSASSA-PSS with SHA-256 and a salt the
// same size as the hash, as RFC 7518 requires.
func NewPS256Signer(key *rsa.PrivateKey) (*RSASigner, error) {
	return newRSASigner(AlgorithmPS256, crypto.SHA256, true, key)
}

// NewPS384Signer returns a signer for RSASSA-PSS with SHA-384.
func NewPS384Signer(key *rsa.PrivateKey) (*RSASigner, error) {
	return newRSASigner(AlgorithmPS384, crypto.SHA384, true, key)
}

// NewPS512Signer returns a signer for RSASSA-PSS with SHA-512.
func NewPS512Signer(key *rsa.PrivateKey) (*RSASigner, error) {
	return newRSASigner(AlgorithmPS512, crypto.SHA512, true, key)
}

// NewRS256Verifier returns a verifier for RSASSA-PKCS1-v1_5 with SHA-256.
func NewRS256Verifier(key *rsa.PublicKey) (*RSAVerifier, error) {
	return newRSAVerifier(AlgorithmRS256, crypto.SHA256, false, key)
}

// NewRS384Verifier returns a verifier for RSASSA-PKCS1-v1_5 with SHA-384.
func NewRS384Verifier(key *rsa.PublicKey) (*RSAVerifier, error) {
	return newRSAVerifier(AlgorithmRS384, crypto.SHA384, false, key)
}

// NewRS512Verifier returns a verifier for RSASSA-PKCS1-v1_5 with SHA-512.
func NewRS512Verifier(key *rsa.PublicKey) (*RSAVerifier, error) {
	return newRSAVerifier(AlgorithmRS512, crypto.SHA512, false, key)
}

// NewPS256Verifier returns a verifier for RSASSA-PSS with SHA-256.
func NewPS256Verifier(key *rsa.PublicKey) (*RSAVerifier, error) {
	return newRSAVerifier(AlgorithmPS256, crypto.SHA256, true, key)
}

// NewPS384Verifier returns a verifier for RSASSA-PSS with SHA-384.
func NewPS384Verifier(key *rsa.PublicKey) (*RSAVerifier, error) {
	return newRSAVerifier(AlgorithmPS384, crypto.SHA384, true, key)
}

// NewPS512Verifier returns a verifier for RSASSA-PSS with SHA-512.
func NewPS512Verifier(key *rsa.PublicKey) (*RSAVerifier, error) {
	return newRSAVerifier(AlgorithmPS512, crypto.SHA512, true, key)
}

// Algorithm returns the alg value this signer was built for.
func (s *RSASigner) Algorithm() string {
	return s.algorithm
}

// Sign hashes signingInput and signs the digest. The signature is as wide as
// the modulus: 256 bytes for a 2048-bit key, which is four times an ECDSA
// signature and dominates the size of the token.
func (s *RSASigner) Sign(signingInput []byte) ([]byte, error) {
	h := s.hash.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	if s.pss {
		signature, err := rsa.SignPSS(rand.Reader, s.key, s.hash, digest, pssOptions(s.hash))
		if err != nil {
			return nil, fmt.Errorf("rsa: %w", err)
		}
		return signature, nil
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, s.hash, digest)
	if err != nil {
		return nil, fmt.Errorf("rsa: %w", err)
	}

	return signature, nil
}

// Algorithm returns the alg value this verifier accepts.
func (v *RSAVerifier) Algorithm() string {
	return v.algorithm
}

// Verify checks the signature against the public key, returning
// [ErrSignatureInvalid] when it does not match.
func (v *RSAVerifier) Verify(signingInput, signature []byte) error {
	h := v.hash.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	var err error
	if v.pss {
		err = rsa.VerifyPSS(v.key, v.hash, digest, signature, pssOptions(v.hash))
	} else {
		err = rsa.VerifyPKCS1v15(v.key, v.hash, digest, signature)
	}
	if err != nil {
		return ErrSignatureInvalid
	}

	return nil
}
