package jwt_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// TestSignArguments covers what Sign refuses before it writes anything.
func TestSignArguments(t *testing.T) {
	s := testSigner(t)

	t.Run("nil claims", func(t *testing.T) {
		if _, err := jwt.Sign(nil, nil, s, jwt.SignOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Sign() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("nil signer", func(t *testing.T) {
		if _, err := jwt.Sign(nil, &jwt.RegisteredClaims{}, nil, jwt.SignOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Sign() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("nil pointer to the registered claims", func(t *testing.T) {
		var c *jwt.RegisteredClaims
		if _, err := jwt.Sign(nil, c, s, jwt.SignOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Sign() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("nil pointer to the registered headers", func(t *testing.T) {
		var h *jwt.RegisteredHeaders
		if _, err := jwt.Sign(h, &jwt.RegisteredClaims{}, s, jwt.SignOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Sign() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("nil header falls back to the registered set", func(t *testing.T) {
		token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s, jwt.SignOptions{})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if got := decodeSegment(t, token, 0); got != `{"typ":"JWT","alg":"HS256"}` {
			t.Errorf("header = %s, want the registered defaults", got)
		}
	})
}

// TestSignWritesTheHeader pins the two header parameters the caller does not
// control. The algorithm comes from the signer and overwrites anything the
// caller put there, which is what makes a mismatch between the declared and the
// actual algorithm impossible to construct.
func TestSignWritesTheHeader(t *testing.T) {
	type header struct {
		jwt.RegisteredHeaders
		Service string `json:"svc,omitempty"`
	}

	s := testSigner(t)
	h := header{Service: "billing"}
	h.Algorithm = "none"
	h.Type = "nonsense"
	h.KeyID = "2024-06"

	token, err := jwt.Sign(&h, &jwt.RegisteredClaims{}, s, jwt.SignOptions{})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(decodeSegment(t, token, 0)), &got); err != nil {
		t.Fatalf("header is not an object: %v", err)
	}

	if got["alg"] != "HS256" {
		t.Errorf("alg = %v, want HS256: the signer decides, not the caller", got["alg"])
	}
	if got["typ"] != "JWT" {
		t.Errorf("typ = %v, want JWT", got["typ"])
	}
	if got["kid"] != "2024-06" {
		t.Errorf("kid = %v, want it carried through untouched", got["kid"])
	}
	if got["svc"] != "billing" {
		t.Errorf("svc = %v, want it carried through untouched", got["svc"])
	}

	if h.Algorithm != "HS256" {
		t.Errorf("Sign is documented to write into the caller's value, alg = %q", h.Algorithm)
	}
}

// TestSignWritesTimeClaims checks that each option lands in the payload, and
// that an unset one writes nothing at all rather than a zero.
func TestSignWritesTimeClaims(t *testing.T) {
	s := testSigner(t)
	exp := time.Unix(1_700_000_060, 0)
	nbf := time.Unix(1_699_999_940, 0)
	iat := time.Unix(1_700_000_000, 0)

	t.Run("all three set", func(t *testing.T) {
		token, err := jwt.Sign(nil, &jwt.RegisteredClaims{}, s, jwt.SignOptions{
			Expiration: exp,
			NotBefore:  nbf,
			IssuedAt:   iat,
		})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		var got map[string]any
		if err := json.Unmarshal([]byte(decodeSegment(t, token, 1)), &got); err != nil {
			t.Fatalf("payload is not an object: %v", err)
		}
		for name, want := range map[string]int64{"exp": exp.Unix(), "nbf": nbf.Unix(), "iat": iat.Unix()} {
			if v, ok := got[name].(float64); !ok || int64(v) != want {
				t.Errorf("%s = %v, want %d", name, got[name], want)
			}
		}
	})

	t.Run("none set", func(t *testing.T) {
		token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s, jwt.SignOptions{})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if got := decodeSegment(t, token, 1); got != `{"sub":"u1"}` {
			t.Errorf("payload = %s, want only the claim that was set", got)
		}
	})
}

// TestSignIsDeterministic matters beyond tidiness: the RFC vectors and any
// golden token depend on the same input producing the same bytes, which it
// would not if Sign read the clock on its own.
func TestSignIsDeterministic(t *testing.T) {
	s := testSigner(t)
	opts := jwt.SignOptions{Expiration: time.Unix(1_700_000_060, 0)}

	first, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s, opts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	second, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s, opts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if first != second {
		t.Errorf("two identical calls produced different tokens:\n%s\n%s", first, second)
	}
}

// TestSignShape checks the compact serialization itself: three segments, joined
// by periods, each base64url with no padding.
func TestSignShape(t *testing.T) {
	s := testSigner(t)

	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s, jwt.SignOptions{})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Errorf("segment %d is empty", i+1)
		}
		if strings.ContainsAny(p, "+/=") {
			t.Errorf("segment %d uses the standard base64 alphabet or padding: %q", i+1, p)
		}
		if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
			t.Errorf("segment %d does not decode: %v", i+1, err)
		}
	}

	if sig, _ := base64.RawURLEncoding.DecodeString(parts[2]); len(sig) != 32 {
		t.Errorf("HS256 signature is %d bytes, want 32", len(sig))
	}
}

// decodeSegment returns segment n of a compact token as text.
func decodeSegment(t *testing.T, token string, n int) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if n >= len(parts) {
		t.Fatalf("token has %d segments, wanted segment %d", len(parts), n)
	}

	b, err := base64.RawURLEncoding.DecodeString(parts[n])
	if err != nil {
		t.Fatalf("segment %d does not decode: %v", n, err)
	}

	return string(b)
}
