package jwk_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/daanila01/jwt"
	"github.com/daanila01/jwt/jwk"
)

// The keys below come from the worked examples in the RFCs, which is what makes
// them worth having: they are documents someone else produced, so reading them
// proves interoperability rather than self-consistency.
const (
	// RFC 7515, Appendix A.3: an EC key on P-256.
	rfc7515A3Key = `{"kty":"EC",
		"crv":"P-256",
		"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}`

	// RFC 7515, Appendix A.4: an EC key on P-521, where a coordinate takes 66
	// bytes because 521 bits does not divide by eight.
	rfc7515A4Key = `{"kty":"EC",
		"crv":"P-521",
		"x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
		"y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
		"d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"}`

	// RFC 8037, Appendix A.1: an Ed25519 key, where d is the 32-byte seed.
	rfc8037Key = `{"kty":"OKP",
		"crv":"Ed25519",
		"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
		"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
)

func TestParseReferenceKeys(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		kty     string
		private bool
	}{
		{"RFC 7515 A.3, P-256", rfc7515A3Key, "EC", true},
		{"RFC 7515 A.4, P-521", rfc7515A4Key, "EC", true},
		{"RFC 8037 A.1, Ed25519", rfc8037Key, "OKP", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := jwk.Parse([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if _, err := k.Public(); err != nil {
				t.Errorf("Public() error = %v", err)
			}
			if _, err := k.Private(); (err != nil) == tt.private {
				t.Errorf("Private() error = %v, want a private half: %v", err, tt.private)
			}
		})
	}
}

// TestReferenceKeyRoundTrip is the check that matters: a key read from someone
// else's document must actually sign and verify.
func TestReferenceKeyRoundTrip(t *testing.T) {
	for _, doc := range []string{rfc7515A3Key, rfc7515A4Key, rfc8037Key} {
		k, err := jwk.Parse([]byte(doc))
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

		t.Run(signer.Algorithm(), func(t *testing.T) {
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

// TestAlgorithmInference covers the asymmetry between key types. A curve names
// exactly one algorithm, so EC and OKP keys need no alg; an RSA key does,
// because nothing in it separates RS256 from PS512.
func TestAlgorithmInference(t *testing.T) {
	t.Run("EC without alg", func(t *testing.T) {
		k, err := jwk.Parse([]byte(rfc7515A3Key))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		v, err := k.Verifier()
		if err != nil {
			t.Fatalf("Verifier() error = %v", err)
		}
		if v.Algorithm() != jwt.AlgorithmES256 {
			t.Errorf("alg = %q, want ES256 inferred from P-256", v.Algorithm())
		}
	})

	t.Run("Ed25519 without alg", func(t *testing.T) {
		k, err := jwk.Parse([]byte(rfc8037Key))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		v, err := k.Verifier()
		if err != nil {
			t.Fatalf("Verifier() error = %v", err)
		}
		if v.Algorithm() != jwt.AlgorithmEdDSA {
			t.Errorf("alg = %q, want EdDSA", v.Algorithm())
		}
	})

	t.Run("RSA without alg is refused", func(t *testing.T) {
		doc := rsaPublicJWK(t, "", "")
		k, err := jwk.Parse(doc)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := k.Verifier(); !errors.Is(err, jwk.ErrKeyInvalid) {
			t.Fatalf("Verifier() error = %v, want %v: nothing says which padding", err, jwk.ErrKeyInvalid)
		}
	})

	t.Run("RSA with alg", func(t *testing.T) {
		k, err := jwk.Parse(rsaPublicJWK(t, "RS256", ""))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		v, err := k.Verifier()
		if err != nil {
			t.Fatalf("Verifier() error = %v", err)
		}
		if v.Algorithm() != jwt.AlgorithmRS256 {
			t.Errorf("alg = %q, want RS256", v.Algorithm())
		}
	})
}

// TestUseIsHonoured pins the check nobody bothers with. A key published for
// encryption must not end up verifying signatures.
func TestUseIsHonoured(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want error
	}{
		{"use sig", string(rsaPublicJWK(t, "RS256", "sig")), nil},
		{"use enc", string(rsaPublicJWK(t, "RS256", "enc")), jwk.ErrKeyNotPermitted},
		{"use absent", string(rsaPublicJWK(t, "RS256", "")), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := jwk.Parse([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if _, err := k.Verifier(); !errors.Is(err, tt.want) {
				t.Fatalf("Verifier() error = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("key_ops without verify", func(t *testing.T) {
		var doc map[string]any
		if err := json.Unmarshal(rsaPublicJWK(t, "RS256", ""), &doc); err != nil {
			t.Fatal(err)
		}
		doc["key_ops"] = []string{"sign"}
		b, _ := json.Marshal(doc)

		k, err := jwk.Parse(b)
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := k.Verifier(); !errors.Is(err, jwk.ErrKeyNotPermitted) {
			t.Fatalf("Verifier() error = %v, want %v", err, jwk.ErrKeyNotPermitted)
		}
	})
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want error
	}{
		{"not json", `{`, jwk.ErrKeyInvalid},
		{"no kty", `{"n":"AQAB","e":"AQAB"}`, jwk.ErrKeyInvalid},
		{"unknown kty", `{"kty":"magic"}`, jwk.ErrKeyUnsupported},
		{"unknown curve", `{"kty":"EC","crv":"P-192","x":"AA","y":"AA"}`, jwk.ErrKeyUnsupported},
		{"OKP on an unsupported curve", `{"kty":"OKP","crv":"Ed448","x":"AA"}`, jwk.ErrKeyUnsupported},
		{"EC without crv", `{"kty":"EC","x":"AA","y":"AA"}`, jwk.ErrKeyInvalid},
		{"RSA without n", `{"kty":"RSA","e":"AQAB"}`, jwk.ErrKeyInvalid},
		{"coordinate of the wrong width", `{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`, jwk.ErrKeyInvalid},
		{"not base64url", `{"kty":"RSA","n":"!!!","e":"AQAB"}`, jwk.ErrKeyInvalid},
		{"oct without k", `{"kty":"oct"}`, jwk.ErrKeyInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := jwk.Parse([]byte(tt.doc)); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestPointNotOnCurve is the check that separates a decoder from a key parser.
// Two numbers of the right length are not a key, and a point off the curve is
// how some attacks against ECDH start.
func TestPointNotOnCurve(t *testing.T) {
	doc := `{"kty":"EC","crv":"P-256",
		"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"}`

	if _, err := jwk.Parse([]byte(doc)); !errors.Is(err, jwk.ErrKeyInvalid) {
		t.Fatalf("Parse() error = %v, want %v", err, jwk.ErrKeyInvalid)
	}
}

// TestHalvesMustMatch checks that a private half belonging to a different key
// is caught, which no amount of field validation would find.
func TestHalvesMustMatch(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(rfc7515A3Key), &doc); err != nil {
		t.Fatal(err)
	}
	doc["d"] = base64.RawURLEncoding.EncodeToString(other.D.FillBytes(make([]byte, 32)))
	b, _ := json.Marshal(doc)

	if _, err := jwk.Parse(b); !errors.Is(err, jwk.ErrKeyInvalid) {
		t.Fatalf("Parse() error = %v, want %v", err, jwk.ErrKeyInvalid)
	}
}

func TestSymmetricKey(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	doc := `{"kty":"oct","alg":"HS256","k":"` + base64.RawURLEncoding.EncodeToString(secret) + `"}`

	k, err := jwk.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	got, err := k.Secret()
	if err != nil {
		t.Fatalf("Secret() error = %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("Secret() = %x, want %x", got, secret)
	}

	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer() error = %v", err)
	}
	verifier, err := k.Verifier()
	if err != nil {
		t.Fatalf("Verifier() error = %v", err)
	}

	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, signer)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := jwt.Parse(token, nil, nil, verifier, jwt.ParseOptions{}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

// rsaPublicJWK builds a JWK for a freshly generated RSA key, since no RFC
// example carries one that is only public.
func rsaPublicJWK(t *testing.T, alg, use string) []byte {
	t.Helper()

	key := testRSAKey(t)
	doc := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	if alg != "" {
		doc["alg"] = alg
	}
	if use != "" {
		doc["use"] = use
	}

	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

var sharedRSA *rsa.PrivateKey

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	if sharedRSA == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		sharedRSA = k
	}

	return sharedRSA
}

var _ = ed25519.PublicKey(nil)
