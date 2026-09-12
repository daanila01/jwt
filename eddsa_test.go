package jwt_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/daanila01/jwt"
)

func edKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	return pub, priv
}

func edPair(t *testing.T) (*jwt.EdDSASigner, *jwt.EdDSAVerifier) {
	t.Helper()

	pub, priv := edKeys(t)

	s, err := jwt.NewEdDSASigner(priv)
	if err != nil {
		t.Fatalf("NewEdDSASigner() error = %v", err)
	}
	v, err := jwt.NewEdDSAVerifier(pub)
	if err != nil {
		t.Fatalf("NewEdDSAVerifier() error = %v", err)
	}

	return s, v
}

// TestEdDSAKeyLength matters more here than elsewhere. ed25519.PrivateKey is a
// plain byte slice, and the standard library panics rather than errors on a
// wrong length, so without a check in the constructor a caller's mistake
// becomes a panic raised inside this package on the first request.
func TestEdDSAKeyLength(t *testing.T) {
	pub, priv := edKeys(t)

	t.Run("private key", func(t *testing.T) {
		tests := []struct {
			name string
			key  ed25519.PrivateKey
			want error
		}{
			{"nil", nil, jwt.ErrKeyInvalid},
			{"empty", ed25519.PrivateKey{}, jwt.ErrKeyInvalid},
			{"too short", priv[:63], jwt.ErrKeyInvalid},
			{"too long", append(append(ed25519.PrivateKey{}, priv...), 0), jwt.ErrKeyInvalid},
			{"the seed alone", ed25519.PrivateKey(priv.Seed()), jwt.ErrKeyInvalid},
			{"exactly right", priv, nil},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, err := jwt.NewEdDSASigner(tt.key)
				if !errors.Is(err, tt.want) {
					t.Fatalf("error = %v, want %v", err, tt.want)
				}
				if tt.want == nil && s == nil {
					t.Fatal("no signer and no error")
				}
				if tt.want != nil && s != nil {
					t.Error("a signer was returned alongside an error")
				}
			})
		}
	})

	t.Run("public key", func(t *testing.T) {
		tests := []struct {
			name string
			key  ed25519.PublicKey
			want error
		}{
			{"nil", nil, jwt.ErrKeyInvalid},
			{"empty", ed25519.PublicKey{}, jwt.ErrKeyInvalid},
			{"too short", pub[:31], jwt.ErrKeyInvalid},
			{"too long", append(append(ed25519.PublicKey{}, pub...), 0), jwt.ErrKeyInvalid},
			{"a private key by mistake", ed25519.PublicKey(priv), jwt.ErrKeyInvalid},
			{"exactly right", pub, nil},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				v, err := jwt.NewEdDSAVerifier(tt.key)
				if !errors.Is(err, tt.want) {
					t.Fatalf("error = %v, want %v", err, tt.want)
				}
				if tt.want == nil && v == nil {
					t.Fatal("no verifier and no error")
				}
				if tt.want != nil && v != nil {
					t.Error("a verifier was returned alongside an error")
				}
			})
		}
	})
}

func TestEdDSAAlgorithmName(t *testing.T) {
	s, v := edPair(t)

	if got := s.Algorithm(); got != jwt.AlgorithmEdDSA {
		t.Errorf("signer Algorithm() = %q, want %q", got, jwt.AlgorithmEdDSA)
	}
	if got := v.Algorithm(); got != jwt.AlgorithmEdDSA {
		t.Errorf("verifier Algorithm() = %q, want %q", got, jwt.AlgorithmEdDSA)
	}

	// The registered name is the scheme, not the curve. Ed25519 would be wrong
	// in the header even though it is the curve in use.
	if jwt.AlgorithmEdDSA != "EdDSA" {
		t.Errorf("AlgorithmEdDSA = %q, want EdDSA", jwt.AlgorithmEdDSA)
	}
}

// TestEdDSAMatchesStandardLibrary signs the same input with crypto/ed25519
// directly. A round trip only shows the package agrees with itself.
func TestEdDSAMatchesStandardLibrary(t *testing.T) {
	pub, priv := edKeys(t)
	input := []byte("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1MSJ9")

	s, err := jwt.NewEdDSASigner(priv)
	if err != nil {
		t.Fatalf("NewEdDSASigner() error = %v", err)
	}
	got, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if want := ed25519.Sign(priv, input); !bytes.Equal(got, want) {
		t.Errorf("Sign() = %x, want %x", got, want)
	}
	if len(got) != ed25519.SignatureSize {
		t.Errorf("signature is %d bytes, want %d", len(got), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, input, got) {
		t.Error("the standard library refuses our signature")
	}
}

// TestEdDSAIsDeterministic is the property that separates EdDSA from ECDSA.
// The nonce comes from the key and the message rather than from randomness, so
// a repeat cannot leak the private key, and a reference vector can be compared
// byte for byte.
func TestEdDSAIsDeterministic(t *testing.T) {
	s, _ := edPair(t)
	input := []byte("header.payload")

	first, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	second, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("two signatures over the same input differ:\n%x\n%x", first, second)
	}
}

func TestEdDSAVerify(t *testing.T) {
	s, v := edPair(t)
	input := []byte("header.payload")

	good, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	_, otherVerifier := edPair(t)

	tests := []struct {
		name      string
		verifier  *jwt.EdDSAVerifier
		input     []byte
		signature []byte
		want      error
	}{
		{"its own signature", v, input, good, nil},
		{"nil signature", v, input, nil, jwt.ErrSignatureInvalid},
		{"empty signature", v, input, []byte{}, jwt.ErrSignatureInvalid},
		{"zeroes of the right length", v, input, make([]byte, ed25519.SignatureSize), jwt.ErrSignatureInvalid},
		{"one bit flipped", v, input, flip(good), jwt.ErrSignatureInvalid},
		{"truncated", v, input, good[:63], jwt.ErrSignatureInvalid},
		{"one byte too long", v, input, append(append([]byte{}, good...), 0), jwt.ErrSignatureInvalid},
		{"right signature, different input", v, []byte("header.other"), good, jwt.ErrSignatureInvalid},
		{"another key's verifier", otherVerifier, input, good, jwt.ErrSignatureInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Verify() panicked: %v", r)
				}
			}()

			if err := tt.verifier.Verify(tt.input, tt.signature); !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEdDSAThroughSignAndParse(t *testing.T) {
	s, v := edPair(t)

	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	h := make(map[string]any)
	var c jwt.RegisteredClaims
	if err := jwt.Parse(token, h, &c, v, jwt.ParseOptions{}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if h["alg"] != jwt.AlgorithmEdDSA {
		t.Errorf("alg = %q, want %q", h["alg"], jwt.AlgorithmEdDSA)
	}
	if c.Subject != "u1" {
		t.Errorf("sub = %q, want u1", c.Subject)
	}

	if sig := strings.Split(token, ".")[2]; len(sig) != 86 {
		t.Errorf("encoded signature is %d characters, want 86 for 64 bytes of base64url", len(sig))
	}
}

// TestEdDSAAgainstOtherFamilies checks that the algorithm comparison in Parse
// refuses a token from a different family in both directions, which is the
// check that stops algorithm confusion.
func TestEdDSAAgainstOtherFamilies(t *testing.T) {
	edSigner, edVerifier := edPair(t)
	hmacSigner := testSigner(t)

	t.Run("EdDSA token, HMAC verifier", func(t *testing.T) {
		token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, edSigner)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if err := jwt.Parse(token, nil, nil, hmacSigner, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrTokenInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrTokenInvalid)
		}
	})

	t.Run("HMAC token, EdDSA verifier", func(t *testing.T) {
		token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, hmacSigner)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if err := jwt.Parse(token, nil, nil, edVerifier, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrTokenInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrTokenInvalid)
		}
	})
}

// TestEdDSAConcurrent exists for the race detector, which sees nothing unless
// something actually runs in parallel.
func TestEdDSAConcurrent(t *testing.T) {
	s, v := edPair(t)
	input := []byte("header.payload")

	want, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				got, err := s.Sign(input)
				if err != nil {
					t.Errorf("Sign() error = %v", err)
					return
				}
				if !bytes.Equal(got, want) {
					t.Errorf("Sign() = %x, want %x", got, want)
					return
				}
				if err := v.Verify(input, got); err != nil {
					t.Errorf("Verify() error = %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestEdDSAKeyIsRetained documents the same ownership contract as HMAC: the
// constructor keeps the caller's slice.
func TestEdDSAKeyIsRetained(t *testing.T) {
	_, priv := edKeys(t)
	kept := append(ed25519.PrivateKey{}, priv...)

	s, err := jwt.NewEdDSASigner(priv)
	if err != nil {
		t.Fatalf("NewEdDSASigner() error = %v", err)
	}
	before, err := s.Sign([]byte("input"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	copy(priv, bytes.Repeat([]byte{0xAA}, len(priv)))
	after, err := s.Sign([]byte("input"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	copy(priv, kept)

	if bytes.Equal(before, after) {
		t.Error("overwriting the caller's slice left the signature unchanged: the documented contract says the key is retained, so update the documentation or the test")
	}
}
