package jwt_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/daanila01/jwt"
)

// TestNewHS256KeyLength pins the rule from RFC 7518: an HMAC key must be at
// least as long as the hash output. Rejecting a short key at construction is
// what keeps a weak secret from reaching production instead of failing on the
// first request.
func TestNewHS256KeyLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		want error
	}{
		{"nil key", nil, jwt.ErrKeyInvalid},
		{"empty key", []byte{}, jwt.ErrKeyInvalid},
		{"one byte short", bytes.Repeat([]byte("k"), 31), jwt.ErrKeyInvalid},
		{"exactly the hash size", bytes.Repeat([]byte("k"), 32), nil},
		{"longer than the hash size", bytes.Repeat([]byte("k"), 64), nil},
		{"longer than the block size", bytes.Repeat([]byte("k"), 200), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := jwt.NewHS256(tt.key)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewHS256() error = %v, want %v", err, tt.want)
			}
			if tt.want == nil && s == nil {
				t.Fatal("NewHS256() returned no signer and no error")
			}
			if tt.want != nil && s != nil {
				t.Error("NewHS256() returned a signer alongside an error")
			}
		})
	}
}

func TestHS256Algorithm(t *testing.T) {
	if got := testSigner(t).Algorithm(); got != jwt.AlgorithmHS256 {
		t.Errorf("Algorithm() = %q, want %q", got, jwt.AlgorithmHS256)
	}
	if jwt.AlgorithmHS256 != "HS256" {
		t.Errorf("AlgorithmHS256 = %q, want the name registered by RFC 7518", jwt.AlgorithmHS256)
	}
}

// TestHS256MatchesStandardLibrary checks the signature against crypto/hmac
// computed independently. A round trip only proves the package agrees with
// itself; this proves it agrees with the algorithm.
func TestHS256MatchesStandardLibrary(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	s, err := jwt.NewHS256(key)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	input := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9")
	got, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	if want := mac.Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("Sign() = %x, want %x", got, want)
	}
}

func TestHS256Verify(t *testing.T) {
	s := testSigner(t)
	input := []byte("header.payload")

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
		{"zeroes of the right length", input, make([]byte, 32), jwt.ErrSignatureInvalid},
		{"one bit flipped", input, flip(good), jwt.ErrSignatureInvalid},
		{"truncated", input, good[:31], jwt.ErrSignatureInvalid},
		{"padded with a trailing byte", input, append(append([]byte{}, good...), 0), jwt.ErrSignatureInvalid},
		{"right signature, different input", []byte("header.other"), good, jwt.ErrSignatureInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Verify(tt.input, tt.signature); !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestHS256Concurrent exists for the race detector. A signer is documented as
// safe to share, and a hash kept in a struct field would break that quietly:
// the corruption is a wrong signature, not a crash. Without a test that
// actually runs in parallel, -race has nothing to observe and stays green.
func TestHS256Concurrent(t *testing.T) {
	s := testSigner(t)
	input := []byte("header.payload")

	want, err := s.Sign(input)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
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
}

// TestHS256ThroughSignAndParse runs the same signer through the public entry
// points from several goroutines at once, which is how it is actually used.
func TestHS256ThroughSignAndParse(t *testing.T) {
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

// TestHS256KeyIsRetained documents the ownership contract: the constructor
// keeps the slice it was given rather than copying it, so a caller that reuses
// or wipes the buffer changes the key underneath the signer.
func TestHS256KeyIsRetained(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))

	s, err := jwt.NewHS256(key)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}
	before, err := s.Sign([]byte("input"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	for i := range key {
		key[i] = 0
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
