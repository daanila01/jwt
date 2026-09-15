package jwk_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/daanila01/jwt"
	"github.com/daanila01/jwt/jwk"
)

// A written key is only worth something if a verifier that fetched it can check
// a token signed by the private half it was cut from. So every supported key
// type goes out through FromPublicKey and MarshalJSON, back in through Parse,
// and a token travels between the two halves.
func TestWriteEveryKeyType(t *testing.T) {
	ec := func(curve elliptic.Curve, sign func(*ecdsa.PrivateKey) (jwt.Signer, error)) func(*testing.T) (crypto.PublicKey, jwt.Signer) {
		return func(t *testing.T) (crypto.PublicKey, jwt.Signer) {
			k, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			s, err := sign(k)
			if err != nil {
				t.Fatal(err)
			}
			return &k.PublicKey, s
		}
	}
	rsaKey := func(sign func(*rsa.PrivateKey) (jwt.Signer, error)) func(*testing.T) (crypto.PublicKey, jwt.Signer) {
		return func(t *testing.T) (crypto.PublicKey, jwt.Signer) {
			k := testRSAKey(t)
			s, err := sign(k)
			if err != nil {
				t.Fatal(err)
			}
			return &k.PublicKey, s
		}
	}

	tests := []struct {
		name string
		alg  string
		key  func(*testing.T) (crypto.PublicKey, jwt.Signer)
	}{
		{"RS256", jwt.AlgorithmRS256, rsaKey(func(k *rsa.PrivateKey) (jwt.Signer, error) { return jwt.NewRS256Signer(k) })},
		{"PS256", jwt.AlgorithmPS256, rsaKey(func(k *rsa.PrivateKey) (jwt.Signer, error) { return jwt.NewPS256Signer(k) })},
		{"ES256", "", ec(elliptic.P256(), func(k *ecdsa.PrivateKey) (jwt.Signer, error) { return jwt.NewES256Signer(k) })},
		{"ES384", "", ec(elliptic.P384(), func(k *ecdsa.PrivateKey) (jwt.Signer, error) { return jwt.NewES384Signer(k) })},
		{"ES512", "", ec(elliptic.P521(), func(k *ecdsa.PrivateKey) (jwt.Signer, error) { return jwt.NewES512Signer(k) })},
		{"EdDSA", "", func(t *testing.T) (crypto.PublicKey, jwt.Signer) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			s, err := jwt.NewEdDSASigner(priv)
			if err != nil {
				t.Fatal(err)
			}
			return pub, s
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, signer := tt.key(t)

			k, err := jwk.FromPublicKey(pub)
			if err != nil {
				t.Fatalf("FromPublicKey() error = %v", err)
			}
			k.ID = "2024-07"
			k.Algorithm = tt.alg
			k.Use = jwk.UseSignature

			doc, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			read, err := jwk.Parse(doc)
			if err != nil {
				t.Fatalf("Parse() error = %v, document %s", err, doc)
			}
			if read.ID != "2024-07" || read.Use != jwk.UseSignature {
				t.Errorf("kid = %q, use = %q, want both to survive the round trip", read.ID, read.Use)
			}

			verifier, err := read.Verifier()
			if err != nil {
				t.Fatalf("Verifier() error = %v", err)
			}
			if verifier.Algorithm() != tt.name {
				t.Errorf("alg = %q, want %q", verifier.Algorithm(), tt.name)
			}

			token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, signer)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			if err := jwt.Parse(token, nil, nil, verifier, jwt.ParseOptions{}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

// TestWriteReferenceKeys writes the RFC examples back out and compares them with
// the originals member by member, which is what proves the encoding matches
// someone else's rather than only this package's own reader.
func TestWriteReferenceKeys(t *testing.T) {
	for name, doc := range map[string]string{
		"RFC 7515 A.3, P-256":   rfc7515A3Key,
		"RFC 7515 A.4, P-521":   rfc7515A4Key,
		"RFC 8037 A.1, Ed25519": rfc8037Key,
	} {
		t.Run(name, func(t *testing.T) {
			k, err := jwk.Parse([]byte(doc))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			written, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			var want, got map[string]any
			if err := json.Unmarshal([]byte(doc), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(written, &got); err != nil {
				t.Fatal(err)
			}
			delete(want, "d")

			if len(got) != len(want) {
				t.Errorf("wrote %v, want %v", got, want)
			}
			for member, value := range want {
				if got[member] != value {
					t.Errorf("%s = %v, want %v", member, got[member], value)
				}
			}
		})
	}
}

// TestWriteNeverCarriesPrivateHalves is the check that matters most here. A key
// read with its private half, then marshalled, must come out public.
func TestWriteNeverCarriesPrivateHalves(t *testing.T) {
	docs := map[string][]byte{
		"RSA":     rsaJWK(t, "RS256"),
		"EC":      ecJWK(t, elliptic.P256(), "P-256", 32, "ES256"),
		"Ed25519": okpJWK(t, "EdDSA"),
	}

	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			k, err := jwk.Parse(doc)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if _, err := k.Private(); err != nil {
				t.Fatalf("the fixture has no private half to leak: %v", err)
			}

			written, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			var members map[string]any
			if err := json.Unmarshal(written, &members); err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
				if _, ok := members[private]; ok {
					t.Errorf("wrote %q: %s", private, written)
				}
			}
		})
	}
}

// TestWriteCoordinatePadding covers the coordinate whose top byte is zero. RFC
// 7518 wants the full width, and a writer that took big.Int.Bytes would trim it
// and produce a key every reader must refuse.
func TestWriteCoordinatePadding(t *testing.T) {
	var key *ecdsa.PrivateKey
	for i := 0; i < 1<<14; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if k.X.BitLen() <= 248 {
			key = k
			break
		}
	}
	if key == nil {
		t.Fatal("no key with a short x coordinate turned up")
	}

	k, err := jwk.FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey() error = %v", err)
	}
	doc, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if _, err := jwk.Parse(doc); err != nil {
		t.Fatalf("Parse() error = %v: the coordinate was not padded", err)
	}
}

func TestFromPublicKeyRejects(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  crypto.PublicKey
		want error
	}{
		{"nil", nil, jwt.ErrArgumentInvalid},
		{"a nil RSA key", (*rsa.PublicKey)(nil), jwk.ErrKeyInvalid},
		{"a nil EC key", (*ecdsa.PublicKey)(nil), jwk.ErrKeyInvalid},
		{"an Ed25519 key of the wrong length", ed25519.PublicKey{1, 2, 3}, jwk.ErrKeyInvalid},
		{"a curve JOSE does not name", &p224.PublicKey, jwk.ErrKeyUnsupported},
		{"a key type JWS does not sign with", x25519.PublicKey(), jwk.ErrKeyUnsupported},
		{"a private key", testRSAKey(t), jwk.ErrKeyUnsupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := jwk.FromPublicKey(tt.key); !errors.Is(err, tt.want) {
				t.Fatalf("FromPublicKey() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestWriteRejectsWhatCannotBeVerified pins the rule that a key goes out only
// if this package could verify with it on the other side.
func TestWriteRejectsWhatCannotBeVerified(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fromPublic := func(pub crypto.PublicKey, alg string) *jwk.Key {
		k, err := jwk.FromPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		k.Algorithm = alg
		return k
	}
	symmetric, err := jwk.Parse(octJWK(t, "HS256", 32))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  *jwk.Key
	}{
		{"an RSA key without alg", fromPublic(&testRSAKey(t).PublicKey, "")},
		{"an RSA key under 2048 bits", fromPublic(&small.PublicKey, jwt.AlgorithmRS256)},
		{"RS256 on an EC key", fromPublic(&ec.PublicKey, jwt.AlgorithmRS256)},
		{"ES384 on a P-256 key", fromPublic(&ec.PublicKey, jwt.AlgorithmES384)},
		{"a symmetric key", symmetric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := json.Marshal(tt.key); !errors.Is(err, jwk.ErrKeyInvalid) {
				t.Fatalf("Marshal() error = %v, want %v", err, jwk.ErrKeyInvalid)
			}
		})
	}
}

// TestMarshalValueAndPointer guards the receiver. With a pointer receiver, a Key
// or Set marshalled by value would skip MarshalJSON and write its exported
// fields, which for a Set is an empty object and for a Key no key at all.
func TestMarshalValueAndPointer(t *testing.T) {
	k, err := jwk.FromPublicKey(&testRSAKey(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.Algorithm = jwt.AlgorithmRS256
	s := jwk.NewSet(k)

	for name, pair := range map[string][2]any{"Key": {k, *k}, "Set": {s, *s}} {
		t.Run(name, func(t *testing.T) {
			byPointer, err := json.Marshal(pair[0])
			if err != nil {
				t.Fatalf("Marshal(pointer) error = %v", err)
			}
			byValue, err := json.Marshal(pair[1])
			if err != nil {
				t.Fatalf("Marshal(value) error = %v", err)
			}
			if string(byPointer) != string(byValue) {
				t.Errorf("by value %s, by pointer %s", byValue, byPointer)
			}
		})
	}
}

// TestWriteSet is the rotation case end to end: the issuer publishes two keys,
// the verifier reads the document and finds each by kid.
func TestWriteSet(t *testing.T) {
	retired, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current, currentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	a, err := jwk.FromPublicKey(&retired.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	a.ID = "2024-06"
	b, err := jwk.FromPublicKey(current)
	if err != nil {
		t.Fatal(err)
	}
	b.ID = "2024-07"

	doc, err := json.Marshal(jwk.NewSet(a, b))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	set, err := jwk.ParseSet(doc)
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}
	if len(set.Keys()) != 2 || len(set.Skipped()) != 0 {
		t.Fatalf("read %d keys and skipped %v, want 2 and none", len(set.Keys()), set.Skipped())
	}

	key, ok := set.ByID("2024-07")
	if !ok {
		t.Fatal("ByID() did not find the current key")
	}
	verifier, err := key.Verifier()
	if err != nil {
		t.Fatalf("Verifier() error = %v", err)
	}
	signer, err := jwt.NewEdDSASigner(currentPriv)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Sign(map[string]any{"kid": "2024-07"}, &jwt.RegisteredClaims{Subject: "u1"}, signer)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := jwt.Parse(token, nil, nil, verifier, jwt.ParseOptions{}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, ok := set.ByID("2024-06"); !ok {
		t.Error("ByID() did not find the retired key")
	}
}

func TestWriteSetRejects(t *testing.T) {
	key := func(kid string) *jwk.Key {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := jwk.FromPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		k.ID = kid
		return k
	}

	t.Run("two keys under one kid", func(t *testing.T) {
		if _, err := json.Marshal(jwk.NewSet(key("same"), key("same"))); !errors.Is(err, jwk.ErrKeyInvalid) {
			t.Fatalf("Marshal() error = %v, want %v", err, jwk.ErrKeyInvalid)
		}
	})

	t.Run("a nil key", func(t *testing.T) {
		if _, err := json.Marshal(jwk.NewSet(key("a"), nil)); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Marshal() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("an unusable key names its position", func(t *testing.T) {
		symmetric, err := jwk.Parse(octJWK(t, "HS256", 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := json.Marshal(jwk.NewSet(key("a"), symmetric)); !errors.Is(err, jwk.ErrKeyInvalid) {
			t.Fatalf("Marshal() error = %v, want %v", err, jwk.ErrKeyInvalid)
		}
	})

	t.Run("keys without kid are not duplicates", func(t *testing.T) {
		if _, err := json.Marshal(jwk.NewSet(key(""), key(""))); err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
	})

	t.Run("an empty set reads back", func(t *testing.T) {
		doc, err := json.Marshal(jwk.NewSet())
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		if string(doc) != `{"keys":[]}` {
			t.Errorf("wrote %s, want an empty array", doc)
		}
		if _, err := jwk.ParseSet(doc); err != nil {
			t.Fatalf("ParseSet() error = %v", err)
		}
	})
}
