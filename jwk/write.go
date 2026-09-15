package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/daanila01/jwt"
)

// FromPublicKey wraps a standard-library public key so that it can be
// published: *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey.
//
// Only a public key goes in, because publishing is the only reason to write
// one. Set [Key.ID] on the result, and [Key.Algorithm] for an RSA key, before
// writing it.
func FromPublicKey(pub crypto.PublicKey) (*Key, error) {
	switch key := pub.(type) {
	case nil:
		return nil, fmt.Errorf("%w: key is nil", jwt.ErrArgumentInvalid)
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return nil, fmt.Errorf("%w: the RSA key is empty", ErrKeyInvalid)
		}
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
			return nil, fmt.Errorf("%w: the EC key is empty", ErrKeyInvalid)
		}
		if _, _, err := curveName(key.Curve); err != nil {
			return nil, err
		}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return nil, fmt.Errorf("%w: the point is not on its curve", ErrKeyInvalid)
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: an Ed25519 key is %d bytes, want %d", ErrKeyInvalid, len(key), ed25519.PublicKeySize)
		}
	default:
		return nil, fmt.Errorf("%w: %T", ErrKeyUnsupported, pub)
	}

	return &Key{public: pub}, nil
}

// MarshalJSON writes the key as a JSON Web Key, and only ever its public half.
//
// A key read from a document that carried d, p, q or k comes out without them:
// a private key must not reach a JWK Set by way of a json.Marshal nobody looked
// at twice. A symmetric key has no public half and is refused.
//
// A key this package could not verify with is refused too: an alg that does
// not fit the key, an RSA key the constructors reject, an RSA key with no alg at
// all. A document like that breaks every relying party that fetches it, and the
// failure belongs where the key is written, not where it is read.
//
// The receiver is a value so that marshalling a Key, and not only a *Key,
// reaches this method rather than the struct's exported fields.
func (k Key) MarshalJSON() ([]byte, error) {
	raw := jwkJSON{
		KeyID:      k.ID,
		Algorithm:  k.Algorithm,
		Use:        k.Use,
		Operations: k.Operations,
	}

	switch pub := k.public.(type) {
	case *rsa.PublicKey:
		raw.KeyType = KeyTypeRSA
		raw.Modulus = encode(pub.N.Bytes())
		raw.Exponent = encode(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		name, size, err := curveName(pub.Curve)
		if err != nil {
			return nil, err
		}
		raw.KeyType = KeyTypeEC
		raw.Curve = name
		raw.X = encode(pub.X.FillBytes(make([]byte, size)))
		raw.Y = encode(pub.Y.FillBytes(make([]byte, size)))
	case ed25519.PublicKey:
		raw.KeyType = KeyTypeOKP
		raw.Curve = "Ed25519"
		raw.X = encode(pub)
	default:
		return nil, fmt.Errorf("%w: this key has no public half", ErrKeyInvalid)
	}

	if _, err := k.verifier(); err != nil {
		return nil, err
	}

	return json.Marshal(raw)
}

// NewSet builds a set to publish, holding the keys in the order given.
func NewSet(keys ...*Key) *Set {
	return &Set{keys: keys}
}

// MarshalJSON writes the set as the document a provider publishes, each key
// through [Key.MarshalJSON].
//
// Two keys under one kid are refused: a verifier looks keys up by kid, so one of
// them would never be found, and which one depends on document order. An empty
// set is written as an empty array, which [ParseSet] reads back.
//
// The receiver is a value for the same reason as on [Key.MarshalJSON].
func (s Set) MarshalJSON() ([]byte, error) {
	out := setJSON{Keys: make([]json.RawMessage, 0, len(s.keys))}
	seen := make(map[string]bool, len(s.keys))

	for i, k := range s.keys {
		if k == nil {
			return nil, fmt.Errorf("%w: key %d is nil", jwt.ErrArgumentInvalid, i)
		}
		if k.ID != "" {
			if seen[k.ID] {
				return nil, fmt.Errorf("%w: kid %q appears twice", ErrKeyInvalid, k.ID)
			}
			seen[k.ID] = true
		}

		b, err := k.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		out.Keys = append(out.Keys, b)
	}

	return json.Marshal(out)
}

// curveName is the inverse of curveFor.
func curveName(c elliptic.Curve) (string, int, error) {
	switch c {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	case elliptic.P521():
		return "P-521", 66, nil
	}

	return "", 0, fmt.Errorf("%w: curve %s", ErrKeyUnsupported, c.Params().Name)
}

func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
