package jwk_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/daanila01/jwt"
	"github.com/daanila01/jwt/jwk"
)

// A JWK is only useful if the key that comes out of it works, so the table
// below writes one for every algorithm the package supports, reads it back, and
// makes a token travel through it.
func TestEveryAlgorithmThroughAJWK(t *testing.T) {
	tests := []struct {
		name string
		doc  func(*testing.T) []byte
	}{
		{"RS256", func(t *testing.T) []byte { return rsaJWK(t, "RS256") }},
		{"RS384", func(t *testing.T) []byte { return rsaJWK(t, "RS384") }},
		{"RS512", func(t *testing.T) []byte { return rsaJWK(t, "RS512") }},
		{"PS256", func(t *testing.T) []byte { return rsaJWK(t, "PS256") }},
		{"PS384", func(t *testing.T) []byte { return rsaJWK(t, "PS384") }},
		{"PS512", func(t *testing.T) []byte { return rsaJWK(t, "PS512") }},

		{"ES256", func(t *testing.T) []byte { return ecJWK(t, elliptic.P256(), "P-256", 32, "ES256") }},
		{"ES384", func(t *testing.T) []byte { return ecJWK(t, elliptic.P384(), "P-384", 48, "ES384") }},
		{"ES512", func(t *testing.T) []byte { return ecJWK(t, elliptic.P521(), "P-521", 66, "ES512") }},

		{"EdDSA", func(t *testing.T) []byte { return okpJWK(t, "EdDSA") }},

		{"HS256", func(t *testing.T) []byte { return octJWK(t, "HS256", 32) }},
		{"HS384", func(t *testing.T) []byte { return octJWK(t, "HS384", 48) }},
		{"HS512", func(t *testing.T) []byte { return octJWK(t, "HS512", 64) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := jwk.Parse(tt.doc(t))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			signer, err := k.Signer()
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			verifier, err := k.Verifier()
			if err != nil {
				t.Fatalf("Verifier() error = %v", err)
			}
			if signer.Algorithm() != tt.name || verifier.Algorithm() != tt.name {
				t.Fatalf("alg = %q and %q, want %q", signer.Algorithm(), verifier.Algorithm(), tt.name)
			}

			token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, signer)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			var c jwt.RegisteredClaims
			if err := jwt.Parse(token, nil, &c, verifier, jwt.ParseOptions{}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if c.Subject != "u1" {
				t.Errorf("sub = %q, want u1", c.Subject)
			}
		})
	}
}

// TestAlgorithmMustMatchTheKey checks the other direction: an alg that does not
// belong to the key type is refused rather than quietly producing something.
func TestAlgorithmMustMatchTheKey(t *testing.T) {
	tests := []struct {
		name string
		doc  []byte
	}{
		{"HS256 on an RSA key", rsaJWK(t, "HS256")},
		{"ES256 on an RSA key", rsaJWK(t, "ES256")},
		{"RS256 on an EC key", ecJWK(t, elliptic.P256(), "P-256", 32, "RS256")},
		{"ES384 on a P-256 key", ecJWK(t, elliptic.P256(), "P-256", 32, "ES384")},
		{"RS256 on an Ed25519 key", okpJWK(t, "RS256")},
		{"ES256 on a symmetric key", octJWK(t, "ES256", 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := jwk.Parse(tt.doc)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if _, err := k.Verifier(); !errors.Is(err, jwk.ErrKeyInvalid) {
				t.Errorf("Verifier() error = %v, want %v", err, jwk.ErrKeyInvalid)
			}
			if _, err := k.Signer(); !errors.Is(err, jwk.ErrKeyInvalid) {
				t.Errorf("Signer() error = %v, want %v", err, jwk.ErrKeyInvalid)
			}
		})
	}
}

// TestPublicOnlyCannotSign covers what a fetched JWK Set actually looks like:
// public halves only, so signing must fail and verifying must not.
func TestPublicOnlyCannotSign(t *testing.T) {
	k, err := jwk.Parse(rsaPublicJWK(t, "RS256", ""))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if _, err := k.Verifier(); err != nil {
		t.Errorf("Verifier() error = %v, want a public key to verify", err)
	}
	if _, err := k.Signer(); !errors.Is(err, jwk.ErrKeyInvalid) {
		t.Errorf("Signer() error = %v, want %v", err, jwk.ErrKeyInvalid)
	}
	if _, err := k.Private(); !errors.Is(err, jwk.ErrKeyInvalid) {
		t.Errorf("Private() error = %v, want %v", err, jwk.ErrKeyInvalid)
	}
	if _, err := k.Secret(); !errors.Is(err, jwk.ErrKeyInvalid) {
		t.Errorf("Secret() error = %v, want %v", err, jwk.ErrKeyInvalid)
	}
}

func TestSymmetricHasNoPublicHalf(t *testing.T) {
	k, err := jwk.Parse(octJWK(t, "HS256", 32))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := k.Public(); !errors.Is(err, jwk.ErrKeyInvalid) {
		t.Errorf("Public() error = %v, want %v", err, jwk.ErrKeyInvalid)
	}
}

// TestMalformedPrivateHalves covers the fields only a private key carries, and
// the mismatch checks that catch two halves belonging to different keys.
func TestMalformedPrivateHalves(t *testing.T) {
	tests := []struct {
		name string
		edit func(map[string]any)
	}{
		{"RSA d is not base64url", func(m map[string]any) { m["d"] = "!!!" }},
		{"RSA p is missing", func(m map[string]any) { delete(m, "p") }},
		{"RSA q is missing", func(m map[string]any) { delete(m, "q") }},
		{"RSA d belongs to another key", func(m map[string]any) {
			m["d"] = base64.RawURLEncoding.EncodeToString(big.NewInt(3).Bytes())
		}},
		{"RSA e does not fit an int", func(m map[string]any) {
			huge := new(big.Int).Lsh(big.NewInt(1), 200)
			m["e"] = base64.RawURLEncoding.EncodeToString(huge.Bytes())
		}},
		{"RSA n is not base64url", func(m map[string]any) { m["n"] = "!!!" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(rsaJWK(t, "RS256"), &doc); err != nil {
				t.Fatal(err)
			}
			tt.edit(doc)
			b, _ := json.Marshal(doc)

			if _, err := jwk.Parse(b); !errors.Is(err, jwk.ErrKeyInvalid) {
				t.Fatalf("Parse() error = %v, want %v", err, jwk.ErrKeyInvalid)
			}
		})
	}

	t.Run("Ed25519 d belongs to another key", func(t *testing.T) {
		var doc map[string]any
		if err := json.Unmarshal(okpJWK(t, "EdDSA"), &doc); err != nil {
			t.Fatal(err)
		}
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		doc["d"] = base64.RawURLEncoding.EncodeToString(other.Seed())
		b, _ := json.Marshal(doc)

		if _, err := jwk.Parse(b); !errors.Is(err, jwk.ErrKeyInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwk.ErrKeyInvalid)
		}
	})

	t.Run("EC d is the wrong width", func(t *testing.T) {
		var doc map[string]any
		if err := json.Unmarshal(ecJWK(t, elliptic.P256(), "P-256", 32, "ES256"), &doc); err != nil {
			t.Fatal(err)
		}
		doc["d"] = base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
		b, _ := json.Marshal(doc)

		if _, err := jwk.Parse(b); !errors.Is(err, jwk.ErrKeyInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwk.ErrKeyInvalid)
		}
	})
}

func rsaJWK(t *testing.T, alg string) []byte {
	t.Helper()

	k := testRSAKey(t)
	return mustJSON(t, map[string]any{
		"kty": "RSA",
		"alg": alg,
		"n":   b64(k.N.Bytes()),
		"e":   b64(big.NewInt(int64(k.E)).Bytes()),
		"d":   b64(k.D.Bytes()),
		"p":   b64(k.Primes[0].Bytes()),
		"q":   b64(k.Primes[1].Bytes()),
	})
}

func ecJWK(t *testing.T, curve elliptic.Curve, name string, size int, alg string) []byte {
	t.Helper()

	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return mustJSON(t, map[string]any{
		"kty": "EC",
		"alg": alg,
		"crv": name,
		"x":   b64(k.X.FillBytes(make([]byte, size))),
		"y":   b64(k.Y.FillBytes(make([]byte, size))),
		"d":   b64(k.D.FillBytes(make([]byte, size))),
	})
}

func okpJWK(t *testing.T, alg string) []byte {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return mustJSON(t, map[string]any{
		"kty": "OKP",
		"alg": alg,
		"crv": "Ed25519",
		"x":   b64(pub),
		"d":   b64(priv.Seed()),
	})
}

func octJWK(t *testing.T, alg string, size int) []byte {
	t.Helper()

	secret := make([]byte, size)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	return mustJSON(t, map[string]any{"kty": "oct", "alg": alg, "k": b64(secret)})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return b
}
