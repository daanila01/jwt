// Package jwk reads keys in the JSON Web Key format of RFC 7517.
//
// This is how keys travel between parties. A service that verifies tokens it
// did not issue fetches its issuer's keys as a JWK Set and picks one by the kid
// in the token's header; the keys arrive as JSON with the numbers written in
// base64url, not as PEM, which is why the standard library cannot read them.
//
// The package turns those documents into keys, and keys into a [jwt.Signer] or
// [jwt.Verifier]. It does not fetch anything. Where the bytes come from, how
// long they are cached and what happens when the issuer is unreachable are
// decisions only the application can make, and a library that made them would
// be one that cannot run offline and is awkward to test.
package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/daanila01/jwt"
)

// Errors this package reports. Match them with [errors.Is].
var (
	// ErrKeyInvalid means the document parsed as JSON but is not a usable key:
	// a missing field, a number that does not fit its curve, a private half
	// that does not match its public one.
	//
	// It is the same value as [jwt.ErrKeyInvalid], not a second one wearing the
	// same name. A key can be refused here, while it is being read, or there,
	// while a signer is built from it, and a caller should not have to know
	// which happened to answer the same way.
	ErrKeyInvalid = jwt.ErrKeyInvalid

	// ErrKeyUnsupported means the key is well formed and this package does not
	// implement its type or curve. A JWK Set from a real provider may hold
	// several of these; they are skipped rather than fatal.
	ErrKeyUnsupported = errors.New("jwk: key type unsupported")

	// ErrKeyNotPermitted means the key forbids what was asked of it, through
	// its use or key_ops field.
	ErrKeyNotPermitted = errors.New("jwk: key not permitted for this use")
)

// Key type values from the IANA registry.
const (
	KeyTypeRSA     = "RSA"
	KeyTypeEC      = "EC"
	KeyTypeOKP     = "OKP"
	KeyTypeOctet   = "oct"
	UseSignature   = "sig"
	UseEncryption  = "enc"
	OperationSign  = "sign"
	OperationVerif = "verify"
)

// Key is one JSON Web Key.
//
// It holds the metadata a provider publishes alongside the key material, which
// is what makes a Set usable: [Key.ID] is what a token's kid names, and
// [Key.Algorithm] is what says how the key is meant to be used.
type Key struct {
	// ID is the kid parameter: the name a token's header uses to say which key
	// signed it. Providers rotate keys and publish both for a while, so this is
	// the only way to tell them apart.
	ID string

	// Algorithm is the alg parameter, and it is optional. When it is absent an
	// EC or OKP key still says enough through its curve, but an RSA key does
	// not: nothing in it distinguishes RS256 from PS512.
	Algorithm string

	// Use is the use parameter, sig or enc. A key published for encryption must
	// not be accepted for signatures, which is what [Key.Verifier] enforces.
	Use string

	// Operations is the key_ops parameter, a finer-grained version of Use.
	Operations []string

	public  crypto.PublicKey
	private crypto.PrivateKey
	secret  []byte // oct keys only
}

// jwkJSON is the wire shape. Every number is base64url of a big-endian integer,
// unpadded, as RFC 7517 requires.
type jwkJSON struct {
	KeyType    string   `json:"kty"`
	KeyID      string   `json:"kid"`
	Algorithm  string   `json:"alg"`
	Use        string   `json:"use"`
	Operations []string `json:"key_ops"`

	Curve string `json:"crv"`

	// RSA
	Modulus  string `json:"n"`
	Exponent string `json:"e"`

	// EC and OKP public, RSA private
	X string `json:"x"`
	Y string `json:"y"`
	D string `json:"d"`

	// RSA private
	P  string `json:"p"`
	Q  string `json:"q"`
	Dp string `json:"dp"`
	Dq string `json:"dq"`
	Qi string `json:"qi"`

	// symmetric
	K string `json:"k"`
}

// Parse reads a single JSON Web Key.
func Parse(data []byte) (*Key, error) {
	var raw jwkJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyInvalid, err)
	}

	return fromJSON(&raw)
}

func fromJSON(raw *jwkJSON) (*Key, error) {
	k := &Key{
		ID:         raw.KeyID,
		Algorithm:  raw.Algorithm,
		Use:        raw.Use,
		Operations: raw.Operations,
	}

	var err error
	switch raw.KeyType {
	case KeyTypeRSA:
		err = k.readRSA(raw)
	case KeyTypeEC:
		err = k.readEC(raw)
	case KeyTypeOKP:
		err = k.readOKP(raw)
	case KeyTypeOctet:
		err = k.readOctet(raw)
	case "":
		return nil, fmt.Errorf("%w: kty is missing", ErrKeyInvalid)
	default:
		return nil, fmt.Errorf("%w: kty %q", ErrKeyUnsupported, raw.KeyType)
	}
	if err != nil {
		return nil, err
	}

	return k, nil
}

// decodeInt reads one base64url big-endian integer.
func decodeInt(name, s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: %s is missing", ErrKeyInvalid, name)
	}

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not base64url: %w", ErrKeyInvalid, name, err)
	}

	return new(big.Int).SetBytes(b), nil
}

// decodeFixed reads a value that must occupy exactly size bytes, which is how
// coordinates are written: padded on the left, never trimmed.
func decodeFixed(name, s string, size int) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: %s is missing", ErrKeyInvalid, name)
	}

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not base64url: %w", ErrKeyInvalid, name, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%w: %s is %d bytes, want %d", ErrKeyInvalid, name, len(b), size)
	}

	return b, nil
}

func (k *Key) readRSA(raw *jwkJSON) error {
	n, err := decodeInt("n", raw.Modulus)
	if err != nil {
		return err
	}
	e, err := decodeInt("e", raw.Exponent)
	if err != nil {
		return err
	}
	if !e.IsInt64() || e.Int64() > 1<<31 {
		return fmt.Errorf("%w: e does not fit in an int", ErrKeyInvalid)
	}

	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	k.public = pub

	if raw.D == "" {
		return nil
	}

	d, err := decodeInt("d", raw.D)
	if err != nil {
		return err
	}
	p, err := decodeInt("p", raw.P)
	if err != nil {
		return err
	}
	q, err := decodeInt("q", raw.Q)
	if err != nil {
		return err
	}

	priv := &rsa.PrivateKey{PublicKey: *pub, D: d, Primes: []*big.Int{p, q}}
	priv.Precompute()
	// Validate catches a private half that does not belong to the public one,
	// which no amount of field checking would.
	if err := priv.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrKeyInvalid, err)
	}
	k.private = priv

	return nil
}

// curveFor maps the crv parameter to a curve, and to the byte width one
// coordinate takes on it. P-521 is 521 bits, so that width is 66 rather than 64.
func curveFor(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil
	case "":
		return nil, 0, fmt.Errorf("%w: crv is missing", ErrKeyInvalid)
	default:
		return nil, 0, fmt.Errorf("%w: crv %q", ErrKeyUnsupported, name)
	}
}

func (k *Key) readEC(raw *jwkJSON) error {
	curve, size, err := curveFor(raw.Curve)
	if err != nil {
		return err
	}

	xb, err := decodeFixed("x", raw.X, size)
	if err != nil {
		return err
	}
	yb, err := decodeFixed("y", raw.Y, size)
	if err != nil {
		return err
	}

	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) {
		return fmt.Errorf("%w: the point is not on %s", ErrKeyInvalid, raw.Curve)
	}

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	k.public = pub

	if raw.D == "" {
		return nil
	}

	db, err := decodeFixed("d", raw.D, size)
	if err != nil {
		return err
	}
	priv := &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(db)}

	// The private scalar must produce the published point, or the two halves
	// belong to different keys.
	px, py := curve.ScalarBaseMult(db)
	if px.Cmp(x) != 0 || py.Cmp(y) != 0 {
		return fmt.Errorf("%w: d does not match x and y", ErrKeyInvalid)
	}
	k.private = priv

	return nil
}

func (k *Key) readOKP(raw *jwkJSON) error {
	if raw.Curve != "Ed25519" {
		if raw.Curve == "" {
			return fmt.Errorf("%w: crv is missing", ErrKeyInvalid)
		}
		return fmt.Errorf("%w: crv %q", ErrKeyUnsupported, raw.Curve)
	}

	xb, err := decodeFixed("x", raw.X, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	pub := ed25519.PublicKey(xb)
	k.public = pub

	if raw.D == "" {
		return nil
	}

	// RFC 8037 stores the 32-byte seed, not the 64-byte expanded form.
	seed, err := decodeFixed("d", raw.D, ed25519.SeedSize)
	if err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if derived := priv.Public().(ed25519.PublicKey); !derived.Equal(pub) {
		return fmt.Errorf("%w: d does not match x", ErrKeyInvalid)
	}
	k.private = priv

	return nil
}

func (k *Key) readOctet(raw *jwkJSON) error {
	if raw.K == "" {
		return fmt.Errorf("%w: k is missing", ErrKeyInvalid)
	}

	b, err := base64.RawURLEncoding.DecodeString(raw.K)
	if err != nil {
		return fmt.Errorf("%w: k is not base64url: %w", ErrKeyInvalid, err)
	}
	k.secret = b

	return nil
}

// Public returns the public half as a standard-library key: *rsa.PublicKey,
// *ecdsa.PublicKey or ed25519.PublicKey.
//
// A symmetric key has no public half and reports [ErrKeyInvalid].
func (k *Key) Public() (crypto.PublicKey, error) {
	if k.public == nil {
		return nil, fmt.Errorf("%w: this key has no public half", ErrKeyInvalid)
	}

	return k.public, nil
}

// Private returns the private half, when the document carried one.
func (k *Key) Private() (crypto.PrivateKey, error) {
	if k.private == nil {
		return nil, fmt.Errorf("%w: this key has no private half", ErrKeyInvalid)
	}

	return k.private, nil
}

// Secret returns the bytes of a symmetric key.
func (k *Key) Secret() ([]byte, error) {
	if k.secret == nil {
		return nil, fmt.Errorf("%w: this key is not symmetric", ErrKeyInvalid)
	}

	return k.secret, nil
}

// permits reports whether the key allows the operation its use and key_ops
// describe. A key published for encryption must not verify signatures, and
// saying so is the whole reason those fields exist.
func (k *Key) permits(op string) error {
	if k.Use != "" && k.Use != UseSignature {
		return fmt.Errorf("%w: use is %q", ErrKeyNotPermitted, k.Use)
	}
	if len(k.Operations) == 0 {
		return nil
	}
	for _, allowed := range k.Operations {
		if allowed == op {
			return nil
		}
	}

	return fmt.Errorf("%w: key_ops is %v", ErrKeyNotPermitted, k.Operations)
}

// Verifier builds a verifier for this key, choosing the algorithm from the
// key's own alg parameter.
//
// An RSA key without alg cannot be resolved: nothing in the key distinguishes
// RS256 from PS512, and guessing would decide a security property on the
// caller's behalf. EC and OKP keys say enough through their curve.
func (k *Key) Verifier() (jwt.Verifier, error) {
	if err := k.permits(OperationVerif); err != nil {
		return nil, err
	}

	alg, err := k.algorithm()
	if err != nil {
		return nil, err
	}

	switch pub := k.public.(type) {
	case *rsa.PublicKey:
		return rsaVerifier(alg, pub)
	case *ecdsa.PublicKey:
		return ecdsaVerifier(alg, pub)
	case ed25519.PublicKey:
		if alg != jwt.AlgorithmEdDSA {
			return nil, fmt.Errorf("%w: alg %q on an Ed25519 key", ErrKeyInvalid, alg)
		}
		return jwt.NewEdDSAVerifier(pub)
	}

	if k.secret != nil {
		return hmacKey(alg, k.secret)
	}

	return nil, fmt.Errorf("%w: no key material", ErrKeyInvalid)
}

// Signer builds a signer for this key. It needs the private half, which a
// published JWK Set never carries.
func (k *Key) Signer() (jwt.Signer, error) {
	if err := k.permits(OperationSign); err != nil {
		return nil, err
	}

	alg, err := k.algorithm()
	if err != nil {
		return nil, err
	}

	switch priv := k.private.(type) {
	case *rsa.PrivateKey:
		return rsaSigner(alg, priv)
	case *ecdsa.PrivateKey:
		return ecdsaSigner(alg, priv)
	case ed25519.PrivateKey:
		if alg != jwt.AlgorithmEdDSA {
			return nil, fmt.Errorf("%w: alg %q on an Ed25519 key", ErrKeyInvalid, alg)
		}
		return jwt.NewEdDSASigner(priv)
	}

	if k.secret != nil {
		return hmacKey(alg, k.secret)
	}

	return nil, fmt.Errorf("%w: this key has no private half", ErrKeyInvalid)
}

// algorithm returns the alg to build with, inferring it from the curve when the
// key did not name one and the curve leaves no choice.
func (k *Key) algorithm() (string, error) {
	if k.Algorithm != "" {
		return k.Algorithm, nil
	}

	switch key := k.public.(type) {
	case ed25519.PublicKey:
		return jwt.AlgorithmEdDSA, nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return jwt.AlgorithmES256, nil
		case elliptic.P384():
			return jwt.AlgorithmES384, nil
		case elliptic.P521():
			return jwt.AlgorithmES512, nil
		}
	}

	return "", fmt.Errorf("%w: alg is missing and cannot be inferred from this key", ErrKeyInvalid)
}

func rsaVerifier(alg string, pub *rsa.PublicKey) (jwt.Verifier, error) {
	switch alg {
	case jwt.AlgorithmRS256:
		return jwt.NewRS256Verifier(pub)
	case jwt.AlgorithmRS384:
		return jwt.NewRS384Verifier(pub)
	case jwt.AlgorithmRS512:
		return jwt.NewRS512Verifier(pub)
	case jwt.AlgorithmPS256:
		return jwt.NewPS256Verifier(pub)
	case jwt.AlgorithmPS384:
		return jwt.NewPS384Verifier(pub)
	case jwt.AlgorithmPS512:
		return jwt.NewPS512Verifier(pub)
	}

	return nil, fmt.Errorf("%w: alg %q on an RSA key", ErrKeyInvalid, alg)
}

func rsaSigner(alg string, priv *rsa.PrivateKey) (jwt.Signer, error) {
	switch alg {
	case jwt.AlgorithmRS256:
		return jwt.NewRS256Signer(priv)
	case jwt.AlgorithmRS384:
		return jwt.NewRS384Signer(priv)
	case jwt.AlgorithmRS512:
		return jwt.NewRS512Signer(priv)
	case jwt.AlgorithmPS256:
		return jwt.NewPS256Signer(priv)
	case jwt.AlgorithmPS384:
		return jwt.NewPS384Signer(priv)
	case jwt.AlgorithmPS512:
		return jwt.NewPS512Signer(priv)
	}

	return nil, fmt.Errorf("%w: alg %q on an RSA key", ErrKeyInvalid, alg)
}

func ecdsaVerifier(alg string, pub *ecdsa.PublicKey) (jwt.Verifier, error) {
	switch alg {
	case jwt.AlgorithmES256:
		return jwt.NewES256Verifier(pub)
	case jwt.AlgorithmES384:
		return jwt.NewES384Verifier(pub)
	case jwt.AlgorithmES512:
		return jwt.NewES512Verifier(pub)
	}

	return nil, fmt.Errorf("%w: alg %q on an EC key", ErrKeyInvalid, alg)
}

func ecdsaSigner(alg string, priv *ecdsa.PrivateKey) (jwt.Signer, error) {
	switch alg {
	case jwt.AlgorithmES256:
		return jwt.NewES256Signer(priv)
	case jwt.AlgorithmES384:
		return jwt.NewES384Signer(priv)
	case jwt.AlgorithmES512:
		return jwt.NewES512Signer(priv)
	}

	return nil, fmt.Errorf("%w: alg %q on an EC key", ErrKeyInvalid, alg)
}

// hmacKey covers oct keys, where one value both signs and verifies.
func hmacKey(alg string, secret []byte) (*jwt.HMAC, error) {
	switch alg {
	case jwt.AlgorithmHS256:
		return jwt.NewHS256(secret)
	case jwt.AlgorithmHS384:
		return jwt.NewHS384(secret)
	case jwt.AlgorithmHS512:
		return jwt.NewHS512(secret)
	}

	return nil, fmt.Errorf("%w: alg %q on a symmetric key", ErrKeyInvalid, alg)
}
