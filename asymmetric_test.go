package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/daanila01/jwt"
)

// Generating RSA keys is slow enough that doing it per subtest would dominate
// the run, so the pair is built once and shared.
var (
	rsaKeyOnce sync.Once
	rsaKey     *rsa.PrivateKey
	rsaKeyErr  error
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	rsaKeyOnce.Do(func() {
		rsaKey, rsaKeyErr = rsa.GenerateKey(rand.Reader, jwt.MinRSAKeyBits)
	})
	if rsaKeyErr != nil {
		t.Fatalf("GenerateKey() error = %v", rsaKeyErr)
	}

	return rsaKey
}

func testECKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	return k
}

// asymmetric describes one algorithm well enough for the shared tests below to
// build a signer and a verifier for it without knowing which family it is.
type asymmetric struct {
	name          string
	alg           string
	signer        func(*testing.T) jwt.Signer
	verifier      func(*testing.T) jwt.Verifier
	otherVerifier func(*testing.T) jwt.Verifier // built from a different key
	deterministic bool
	sigLen        int // 0 when the length is not fixed by the algorithm
}

func asymmetricAlgorithms() []asymmetric {
	ec := func(name, alg string, curve elliptic.Curve, sigLen int,
		newS func(*ecdsa.PrivateKey) (*jwt.ECDSASigner, error),
		newV func(*ecdsa.PublicKey) (*jwt.ECDSAVerifier, error),
	) asymmetric {
		var key *ecdsa.PrivateKey
		var once sync.Once
		get := func(t *testing.T) *ecdsa.PrivateKey {
			once.Do(func() { key = testECKey(t, curve) })
			return key
		}

		return asymmetric{
			name: name,
			alg:  alg,
			signer: func(t *testing.T) jwt.Signer {
				s, err := newS(get(t))
				if err != nil {
					t.Fatalf("signer: %v", err)
				}
				return s
			},
			verifier: func(t *testing.T) jwt.Verifier {
				v, err := newV(&get(t).PublicKey)
				if err != nil {
					t.Fatalf("verifier: %v", err)
				}
				return v
			},
			otherVerifier: func(t *testing.T) jwt.Verifier {
				v, err := newV(&testECKey(t, curve).PublicKey)
				if err != nil {
					t.Fatalf("verifier: %v", err)
				}
				return v
			},
			sigLen: sigLen,
		}
	}

	rs := func(name, alg string,
		newS func(*rsa.PrivateKey) (*jwt.RSASigner, error),
		newV func(*rsa.PublicKey) (*jwt.RSAVerifier, error),
		deterministic bool,
	) asymmetric {
		return asymmetric{
			name: name,
			alg:  alg,
			signer: func(t *testing.T) jwt.Signer {
				s, err := newS(testRSAKey(t))
				if err != nil {
					t.Fatalf("signer: %v", err)
				}
				return s
			},
			verifier: func(t *testing.T) jwt.Verifier {
				v, err := newV(&testRSAKey(t).PublicKey)
				if err != nil {
					t.Fatalf("verifier: %v", err)
				}
				return v
			},
			otherVerifier: func(t *testing.T) jwt.Verifier {
				other, err := rsa.GenerateKey(rand.Reader, jwt.MinRSAKeyBits)
				if err != nil {
					t.Fatalf("GenerateKey() error = %v", err)
				}
				v, err := newV(&other.PublicKey)
				if err != nil {
					t.Fatalf("verifier: %v", err)
				}
				return v
			},
			deterministic: deterministic,
			sigLen:        jwt.MinRSAKeyBits / 8,
		}
	}

	return []asymmetric{
		ec("ES256", jwt.AlgorithmES256, elliptic.P256(), 64, jwt.NewES256Signer, jwt.NewES256Verifier),
		ec("ES384", jwt.AlgorithmES384, elliptic.P384(), 96, jwt.NewES384Signer, jwt.NewES384Verifier),
		// P-521 is 521 bits, so a coordinate takes 66 bytes and the pair 132.
		ec("ES512", jwt.AlgorithmES512, elliptic.P521(), 132, jwt.NewES512Signer, jwt.NewES512Verifier),

		rs("RS256", jwt.AlgorithmRS256, jwt.NewRS256Signer, jwt.NewRS256Verifier, true),
		rs("RS384", jwt.AlgorithmRS384, jwt.NewRS384Signer, jwt.NewRS384Verifier, true),
		rs("RS512", jwt.AlgorithmRS512, jwt.NewRS512Signer, jwt.NewRS512Verifier, true),

		// PSS salts every signature, so two over the same input differ.
		rs("PS256", jwt.AlgorithmPS256, jwt.NewPS256Signer, jwt.NewPS256Verifier, false),
		rs("PS384", jwt.AlgorithmPS384, jwt.NewPS384Signer, jwt.NewPS384Verifier, false),
		rs("PS512", jwt.AlgorithmPS512, jwt.NewPS512Signer, jwt.NewPS512Verifier, false),
	}
}

func TestAsymmetricAlgorithmName(t *testing.T) {
	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			if got := a.signer(t).Algorithm(); got != a.alg {
				t.Errorf("signer Algorithm() = %q, want %q", got, a.alg)
			}
			if got := a.verifier(t).Algorithm(); got != a.alg {
				t.Errorf("verifier Algorithm() = %q, want %q", got, a.alg)
			}
			if a.alg != a.name {
				t.Errorf("registered name is %q, want %q", a.alg, a.name)
			}
		})
	}
}

func TestAsymmetricSignatureLength(t *testing.T) {
	input := []byte("header.payload")

	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			sig, err := a.signer(t).Sign(input)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			if len(sig) != a.sigLen {
				t.Errorf("signature is %d bytes, want %d", len(sig), a.sigLen)
			}
		})
	}
}

// TestAsymmetricDeterminism separates the two kinds. RS repeats itself because
// PKCS#1 v1.5 padding is fixed; ES and PS do not, because each draws fresh
// randomness. A reference vector can only be reproduced for the first kind.
func TestAsymmetricDeterminism(t *testing.T) {
	input := []byte("header.payload")

	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s := a.signer(t)

			first, err := s.Sign(input)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			second, err := s.Sign(input)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			if got := bytes.Equal(first, second); got != a.deterministic {
				t.Errorf("two signatures identical = %v, want %v", got, a.deterministic)
			}
		})
	}
}

func TestAsymmetricVerify(t *testing.T) {
	input := []byte("header.payload")

	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s, v := a.signer(t), a.verifier(t)

			good, err := s.Sign(input)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			tests := []struct {
				name      string
				verifier  jwt.Verifier
				input     []byte
				signature []byte
				want      error
			}{
				{"its own signature", v, input, good, nil},
				{"nil signature", v, input, nil, jwt.ErrSignatureInvalid},
				{"empty signature", v, input, []byte{}, jwt.ErrSignatureInvalid},
				{"zeroes of the right length", v, input, make([]byte, len(good)), jwt.ErrSignatureInvalid},
				{"one bit flipped", v, input, flip(good), jwt.ErrSignatureInvalid},
				{"truncated", v, input, good[:len(good)-1], jwt.ErrSignatureInvalid},
				{"one byte too long", v, input, append(append([]byte{}, good...), 0), jwt.ErrSignatureInvalid},
				{"right signature, different input", v, []byte("header.other"), good, jwt.ErrSignatureInvalid},
				{"another key's verifier", a.otherVerifier(t), input, good, jwt.ErrSignatureInvalid},
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
		})
	}
}

func TestAsymmetricThroughSignAndParse(t *testing.T) {
	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, a.signer(t))
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			h := make(map[string]any)
			var c jwt.RegisteredClaims
			if err := jwt.Parse(token, &h, &c, a.verifier(t), jwt.ParseOptions{}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if h["alg"] != a.alg {
				t.Errorf("alg = %q, want %q", h["alg"], a.alg)
			}
			if c.Subject != "u1" {
				t.Errorf("sub = %q, want u1", c.Subject)
			}
		})
	}
}

// TestAsymmetricCrossAlgorithm is the algorithm-confusion check across every
// pair: a token signed with one algorithm must never pass a verifier built for
// another, and the refusal comes from the alg comparison in Parse rather than
// from the cryptography.
func TestAsymmetricCrossAlgorithm(t *testing.T) {
	all := asymmetricAlgorithms()

	for _, signing := range all {
		token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, signing.signer(t))
		if err != nil {
			t.Fatalf("%s: Sign() error = %v", signing.name, err)
		}

		for _, verifying := range all {
			if signing.name == verifying.name {
				continue
			}

			t.Run(signing.name+" verified as "+verifying.name, func(t *testing.T) {
				if err := jwt.Parse(token, nil, nil, verifying.verifier(t), jwt.ParseOptions{}); !errors.Is(err, jwt.ErrTokenInvalid) {
					t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrTokenInvalid)
				}
			})
		}
	}
}

// TestECDSARejectsTheWrongCurve is the check that has no counterpart in the
// other families. A P-384 key will happily sign anything, so without this the
// algorithm in the header would claim P-256 while the signature used another
// curve entirely.
func TestECDSARejectsTheWrongCurve(t *testing.T) {
	p256 := testECKey(t, elliptic.P256())
	p384 := testECKey(t, elliptic.P384())
	p521 := testECKey(t, elliptic.P521())

	tests := []struct {
		name   string
		signer func() (*jwt.ECDSASigner, error)
	}{
		{"ES256 with a P-384 key", func() (*jwt.ECDSASigner, error) { return jwt.NewES256Signer(p384) }},
		{"ES256 with a P-521 key", func() (*jwt.ECDSASigner, error) { return jwt.NewES256Signer(p521) }},
		{"ES384 with a P-256 key", func() (*jwt.ECDSASigner, error) { return jwt.NewES384Signer(p256) }},
		{"ES512 with a P-256 key", func() (*jwt.ECDSASigner, error) { return jwt.NewES512Signer(p256) }},
		{"ES256 with a nil key", func() (*jwt.ECDSASigner, error) { return jwt.NewES256Signer(nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.signer()
			if !errors.Is(err, jwt.ErrKeyInvalid) {
				t.Fatalf("error = %v, want %v", err, jwt.ErrKeyInvalid)
			}
			if s != nil {
				t.Error("a signer was returned alongside an error")
			}
		})
	}

	t.Run("the matching curve is accepted", func(t *testing.T) {
		if _, err := jwt.NewES256Signer(p256); err != nil {
			t.Fatalf("NewES256Signer() error = %v", err)
		}
		if _, err := jwt.NewES384Verifier(&p384.PublicKey); err != nil {
			t.Fatalf("NewES384Verifier() error = %v", err)
		}
	})
}

// TestRSARejectsWeakKeys pins the floor. A 1024-bit modulus is within reach of
// a determined attacker and a 512-bit one falls to a laptop, so both are
// refused when the signer is built rather than trusted at run time.
func TestRSARejectsWeakKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	tests := []struct {
		name string
		call func() error
	}{
		{"RS256 signer, 1024-bit key", func() error { _, err := jwt.NewRS256Signer(weak); return err }},
		{"RS256 verifier, 1024-bit key", func() error { _, err := jwt.NewRS256Verifier(&weak.PublicKey); return err }},
		{"PS256 signer, 1024-bit key", func() error { _, err := jwt.NewPS256Signer(weak); return err }},
		{"RS512 signer, nil key", func() error { _, err := jwt.NewRS512Signer(nil); return err }},
		{"PS384 verifier, nil key", func() error { _, err := jwt.NewPS384Verifier(nil); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, jwt.ErrKeyInvalid) {
				t.Fatalf("error = %v, want %v", err, jwt.ErrKeyInvalid)
			}
		})
	}

	t.Run("the minimum is accepted", func(t *testing.T) {
		if _, err := jwt.NewRS256Signer(testRSAKey(t)); err != nil {
			t.Fatalf("NewRS256Signer() error = %v", err)
		}
	})
}

// TestRSAAndPSSShareKeys checks that the two padding schemes are separate: a
// signature made under one must not verify under the other, even though both
// use the same key pair.
func TestRSAAndPSSShareKeys(t *testing.T) {
	key := testRSAKey(t)
	input := []byte("header.payload")

	pkcs, err := jwt.NewRS256Signer(key)
	if err != nil {
		t.Fatalf("NewRS256Signer() error = %v", err)
	}
	pss, err := jwt.NewPS256Verifier(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewPS256Verifier() error = %v", err)
	}

	sig, err := pkcs.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if err := pss.Verify(input, sig); !errors.Is(err, jwt.ErrSignatureInvalid) {
		t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrSignatureInvalid)
	}
}

func TestAsymmetricConcurrent(t *testing.T) {
	input := []byte("header.payload")

	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s, v := a.signer(t), a.verifier(t)

			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 4; j++ {
						sig, err := s.Sign(input)
						if err != nil {
							t.Errorf("Sign() error = %v", err)
							return
						}
						if err := v.Verify(input, sig); err != nil {
							t.Errorf("Verify() error = %v", err)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

// TestECDSASignatureIsRawNotDER is the check that would have caught the most
// likely mistake here. Go's SignASN1 wraps the pair in ASN.1, whose length
// varies and which starts with a SEQUENCE tag; JOSE wants the two halves plain.
func TestECDSASignatureIsRawNotDER(t *testing.T) {
	key := testECKey(t, elliptic.P256())

	s, err := jwt.NewES256Signer(key)
	if err != nil {
		t.Fatalf("NewES256Signer() error = %v", err)
	}
	sig, err := s.Sign([]byte("header.payload"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64: DER would be around 70 and vary", len(sig))
	}
	if sig[0] == 0x30 {
		// Not conclusive on its own, since a coordinate may start with 0x30,
		// but combined with the fixed length it says the shape is right.
		t.Logf("first byte is 0x30, which is also the ASN.1 SEQUENCE tag; the fixed length rules DER out")
	}

	// A DER-encoded signature must be refused rather than silently split.
	der, err := ecdsa.SignASN1(rand.Reader, key, hashFor(t, "header.payload"))
	if err != nil {
		t.Fatalf("SignASN1() error = %v", err)
	}
	v, err := jwt.NewES256Verifier(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewES256Verifier() error = %v", err)
	}
	if err := v.Verify([]byte("header.payload"), der); !errors.Is(err, jwt.ErrSignatureInvalid) {
		t.Fatalf("Verify() accepted a DER signature: %v", err)
	}
}

func hashFor(t *testing.T, s string) []byte {
	t.Helper()

	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestAsymmetricTokenShape(t *testing.T) {
	for _, a := range asymmetricAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, a.signer(t))
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Fatalf("token has %d segments, want 3", len(parts))
			}
			if strings.ContainsAny(token, "+/=") {
				t.Error("token uses the standard base64 alphabet or padding")
			}
		})
	}
}

// TestAsymmetricVerifierKeyChecks covers the verifier halves of the key
// validation. They are separate constructors and so separate branches, and a
// service that only verifies is exactly the one that will hit them.
func TestAsymmetricVerifierKeyChecks(t *testing.T) {
	p256 := testECKey(t, elliptic.P256())
	p384 := testECKey(t, elliptic.P384())

	tests := []struct {
		name string
		call func() error
	}{
		{"ES256 verifier, P-384 key", func() error { _, err := jwt.NewES256Verifier(&p384.PublicKey); return err }},
		{"ES384 verifier, P-256 key", func() error { _, err := jwt.NewES384Verifier(&p256.PublicKey); return err }},
		{"ES512 verifier, P-256 key", func() error { _, err := jwt.NewES512Verifier(&p256.PublicKey); return err }},
		{"ES256 verifier, nil key", func() error { _, err := jwt.NewES256Verifier(nil); return err }},
		{"ES384 signer, nil key", func() error { _, err := jwt.NewES384Signer(nil); return err }},
		{"ES512 signer, nil key", func() error { _, err := jwt.NewES512Signer(nil); return err }},

		// A key value with no curve at all: the error message must name it
		// without dereferencing anything.
		{"ES256 signer, key with no curve", func() error { _, err := jwt.NewES256Signer(&ecdsa.PrivateKey{}); return err }},
		{"ES256 verifier, key with no curve", func() error { _, err := jwt.NewES256Verifier(&ecdsa.PublicKey{}); return err }},

		// An RSA key value with no modulus, which is what a zero struct is.
		{"RS256 signer, key with no modulus", func() error { _, err := jwt.NewRS256Signer(&rsa.PrivateKey{}); return err }},
		{"RS256 verifier, key with no modulus", func() error { _, err := jwt.NewRS256Verifier(&rsa.PublicKey{}); return err }},
		{"PS512 signer, key with no modulus", func() error { _, err := jwt.NewPS512Signer(&rsa.PrivateKey{}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("constructor panicked: %v", r)
				}
			}()

			if err := tt.call(); !errors.Is(err, jwt.ErrKeyInvalid) {
				t.Fatalf("error = %v, want %v", err, jwt.ErrKeyInvalid)
			}
		})
	}
}
