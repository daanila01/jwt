package jwt_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"strings"
	"sync"
	"testing"

	"github.com/daanila01/jwt"
)

// hmacAlgorithms is the one place the family is listed. Everything below loops
// over it, so a fourth member would be covered by adding a line here.
type hmacAlgorithm struct {
	name    string
	alg     string
	new     func([]byte) (*jwt.HMAC, error)
	newHash func() hash.Hash
	size    int // hash output, which is both the signature length and the key minimum
}

func hmacAlgorithms() []hmacAlgorithm {
	return []hmacAlgorithm{
		{"HS256", jwt.AlgorithmHS256, jwt.NewHS256, sha256.New, 32},
		{"HS384", jwt.AlgorithmHS384, jwt.NewHS384, sha512.New384, 48},
		{"HS512", jwt.AlgorithmHS512, jwt.NewHS512, sha512.New, 64},
	}
}

func key(n int) []byte { return bytes.Repeat([]byte("k"), n) }

// TestHMACKeyLength pins the rule from RFC 7518: the key must be at least as
// long as the hash output. Refusing a short key when the signer is built is
// what keeps a weak secret from reaching production instead of failing on the
// first request.
func TestHMACKeyLength(t *testing.T) {
	for _, a := range hmacAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			tests := []struct {
				name string
				key  []byte
				want error
			}{
				{"nil", nil, jwt.ErrKeyInvalid},
				{"empty", []byte{}, jwt.ErrKeyInvalid},
				{"one byte short", key(a.size - 1), jwt.ErrKeyInvalid},
				{"exactly the hash size", key(a.size), nil},
				{"longer", key(a.size * 2), nil},
				{"longer than the block", key(256), nil},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					s, err := a.new(tt.key)
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
	}
}

// TestHMACAlgorithmName checks that each constructor reports the value that
// goes into the alg header.
func TestHMACAlgorithmName(t *testing.T) {
	for _, a := range hmacAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s, err := a.new(key(a.size))
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			if got := s.Algorithm(); got != a.alg {
				t.Errorf("Algorithm() = %q, want %q", got, a.alg)
			}
			if a.alg != a.name {
				t.Errorf("the registered name is %q, want %q", a.alg, a.name)
			}
		})
	}
}

// TestHMACMatchesStandardLibrary computes the same signature with crypto/hmac
// directly. A round trip only shows the package agrees with itself; this shows
// it agrees with the algorithm it claims to implement.
func TestHMACMatchesStandardLibrary(t *testing.T) {
	input := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9")

	for _, a := range hmacAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			k := key(a.size)

			s, err := a.new(k)
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			got, err := s.Sign(input)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			mac := hmac.New(a.newHash, k)
			mac.Write(input)
			want := mac.Sum(nil)

			if !bytes.Equal(got, want) {
				t.Errorf("Sign() = %x, want %x", got, want)
			}
			if len(got) != a.size {
				t.Errorf("signature is %d bytes, want %d", len(got), a.size)
			}
		})
	}
}

func TestHMACVerify(t *testing.T) {
	input := []byte("header.payload")

	for _, a := range hmacAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s, err := a.new(key(a.size))
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
			good, err := s.Sign(input)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			tests := []struct {
				name      string
				input     []byte
				signature []byte
				want      error
			}{
				{"its own signature", input, good, nil},
				{"nil signature", input, nil, jwt.ErrSignatureInvalid},
				{"empty signature", input, []byte{}, jwt.ErrSignatureInvalid},
				{"zeroes of the right length", input, make([]byte, a.size), jwt.ErrSignatureInvalid},
				{"one bit flipped", input, flip(good), jwt.ErrSignatureInvalid},
				{"truncated", input, good[:a.size-1], jwt.ErrSignatureInvalid},
				{"one byte too long", input, append(append([]byte{}, good...), 0), jwt.ErrSignatureInvalid},
				{"right signature, different input", []byte("header.other"), good, jwt.ErrSignatureInvalid},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if err := s.Verify(tt.input, tt.signature); !errors.Is(err, tt.want) {
						t.Fatalf("Verify() error = %v, want %v", err, tt.want)
					}
				})
			}
		})
	}
}

// TestHMACSignaturesDiffer checks that the three are actually different
// algorithms and not the same one under three names.
func TestHMACSignaturesDiffer(t *testing.T) {
	input := []byte("header.payload")
	seen := map[string]string{}

	for _, a := range hmacAlgorithms() {
		s, err := a.new(key(64)) // one key long enough for all three
		if err != nil {
			t.Fatalf("%s: constructor error = %v", a.name, err)
		}
		sig, err := s.Sign(input)
		if err != nil {
			t.Fatalf("%s: Sign() error = %v", a.name, err)
		}

		hexed := string(sig)
		if other, ok := seen[hexed]; ok {
			t.Errorf("%s produced the same signature as %s", a.name, other)
		}
		seen[hexed] = a.name
	}
}

// TestHMACCrossAlgorithm checks that a signature made with one hash is refused
// by another, even though the key is the same. Without this, a mix-up between
// two of the family would go unnoticed whenever the lengths happened to match.
func TestHMACCrossAlgorithm(t *testing.T) {
	input := []byte("header.payload")
	k := key(64)

	for _, signing := range hmacAlgorithms() {
		for _, verifying := range hmacAlgorithms() {
			if signing.name == verifying.name {
				continue
			}

			t.Run(signing.name+" verified as "+verifying.name, func(t *testing.T) {
				signer, err := signing.new(k)
				if err != nil {
					t.Fatalf("constructor error = %v", err)
				}
				verifier, err := verifying.new(k)
				if err != nil {
					t.Fatalf("constructor error = %v", err)
				}

				sig, err := signer.Sign(input)
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}
				if err := verifier.Verify(input, sig); !errors.Is(err, jwt.ErrSignatureInvalid) {
					t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrSignatureInvalid)
				}
			})
		}
	}
}

// TestHMACThroughSignAndParse runs each algorithm through the public entry
// points, and checks that the header names the one that was actually used.
func TestHMACThroughSignAndParse(t *testing.T) {
	for _, a := range hmacAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s, err := a.new(key(a.size))
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}

			token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s, jwt.SignOptions{})
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			var (
				h jwt.RegisteredHeaders
				c jwt.RegisteredClaims
			)
			if err := jwt.Parse(token, &h, &c, s, jwt.ParseOptions{}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if h.Algorithm != a.alg {
				t.Errorf("alg = %q, want %q", h.Algorithm, a.alg)
			}
			if c.Subject != "u1" {
				t.Errorf("sub = %q, want u1", c.Subject)
			}
		})
	}
}

// TestHMACRejectsAnotherFamilyMember is the same check one level up: a token
// signed with HS256 must not pass a verifier built for HS384, and the refusal
// must come from the algorithm comparison rather than from the signature.
func TestHMACRejectsAnotherFamilyMember(t *testing.T) {
	k := key(64)

	signer, err := jwt.NewHS256(k)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}
	verifier, err := jwt.NewHS384(k)
	if err != nil {
		t.Fatalf("NewHS384() error = %v", err)
	}

	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, signer, jwt.SignOptions{})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if err := jwt.Parse(token, nil, nil, verifier, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrTokenInvalid)
	}
}

// TestHMACConcurrent exists for the race detector. A signer is documented as
// safe to share, and a hash kept on the struct would break that quietly: the
// damage is a wrong signature, not a crash. Without something running in
// parallel, -race has nothing to observe and stays green either way.
func TestHMACConcurrent(t *testing.T) {
	for _, a := range hmacAlgorithms() {
		t.Run(a.name, func(t *testing.T) {
			s, err := a.new(key(a.size))
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
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
					for j := 0; j < 100; j++ {
						got, err := s.Sign(input)
						if err != nil {
							t.Errorf("Sign() error = %v", err)
							return
						}
						if !bytes.Equal(got, want) {
							t.Errorf("Sign() = %x, want %x", got, want)
							return
						}
						if err := s.Verify(input, got); err != nil {
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

// TestHMACThroughSignAndParseConcurrent shares one signer across goroutines the
// way a service does, through the public entry points.
func TestHMACThroughSignAndParseConcurrent(t *testing.T) {
	s := testSigner(t)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := jwt.RegisteredClaims{Subject: "u1"}
			token, err := jwt.Sign(nil, &c, s, jwt.SignOptions{})
			if err != nil {
				t.Errorf("Sign() error = %v", err)
				return
			}
			var out jwt.RegisteredClaims
			if err := jwt.Parse(token, nil, &out, s, jwt.ParseOptions{}); err != nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
			if out.Subject != "u1" {
				t.Errorf("sub = %q, want u1", out.Subject)
			}
		}()
	}
	wg.Wait()
}

// TestHMACKeyIsRetained documents the ownership contract: the constructor keeps
// the slice it was given rather than copying it, so a caller who reuses or
// wipes the buffer changes the key underneath the signer.
func TestHMACKeyIsRetained(t *testing.T) {
	k := []byte(strings.Repeat("k", 32))

	s, err := jwt.NewHS256(k)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}
	before, err := s.Sign([]byte("input"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	for i := range k {
		k[i] = 0
	}
	after, err := s.Sign([]byte("input"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if bytes.Equal(before, after) {
		t.Error("wiping the caller's slice left the signature unchanged: the documented contract says the key is retained, so update the documentation or the test")
	}
}

func flip(b []byte) []byte {
	out := append([]byte{}, b...)
	out[0] ^= 0x01
	return out
}
