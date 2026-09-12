package jwt_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/daanila01/jwt"
)

// Claims arrive as any, so a nil can reach this package in two shapes. A
// literal nil is easy. A nil pointer stored in an interface is not equal to
// nil, and marshalling it produces the JSON literal null: a token this package
// would issue and then refuse to parse. Both must be refused instead.
//
// Headers are a map, which has no such trap: a nil map reads as empty and the
// package fills in one of its own.

type nilClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id,omitempty"`
}

func TestSignRejectsEveryShapeOfNilClaims(t *testing.T) {
	s := testSigner(t)

	var (
		registered *jwt.RegisteredClaims
		own        *nilClaims
		asMap      map[string]any
	)

	tests := []struct {
		name string
		sign func() (string, error)
		want error
	}{
		{"literal nil", func() (string, error) {
			return jwt.Sign(nil, nil, s)
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to the registered set", func() (string, error) {
			return jwt.Sign(nil, registered, s)
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to a caller's own type", func() (string, error) {
			return jwt.Sign(nil, own, s)
		}, jwt.ErrArgumentInvalid},
		{"nil map of claims", func() (string, error) {
			return jwt.Sign(nil, asMap, s)
		}, jwt.ErrArgumentInvalid},

		// A live but empty value is not a mistake: a token with no claims at
		// all is unusual, not invalid.
		{"an empty registered set", func() (string, error) {
			return jwt.Sign(nil, &jwt.RegisteredClaims{}, s)
		}, nil},
		{"an empty map", func() (string, error) {
			return jwt.Sign(nil, map[string]any{}, s)
		}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Sign() panicked instead of returning an error: %v", r)
				}
			}()

			token, err := tt.sign()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Sign() error = %v, want %v", err, tt.want)
			}
			if tt.want != nil {
				return
			}
			if body := strings.Split(token, ".")[1]; body == "bnVsbA" {
				t.Error("the payload is the JSON literal null")
			}
		})
	}
}

func TestSignAcceptsANilHeader(t *testing.T) {
	s := testSigner(t)

	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got := decodeSegment(t, token, 0); got != `{"alg":"HS256"}` {
		t.Errorf("header = %s, want only what the package writes", got)
	}
}

func TestParseAcceptsNilDestinations(t *testing.T) {
	v := testSigner(t)
	token := signHS256(t, testHeaderJSON, `{"sub":"u1"}`)

	t.Run("both nil still verifies", func(t *testing.T) {
		if err := jwt.Parse(token, nil, nil, v, jwt.ParseOptions{}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		forged := token[:len(token)-4] + "AAAA"
		if err := jwt.Parse(forged, nil, nil, v, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrSignatureInvalid) {
			t.Fatalf("a forged token passed while parsing into nothing: %v", err)
		}
	})

	t.Run("nil header, live claims", func(t *testing.T) {
		var c jwt.RegisteredClaims
		if err := jwt.Parse(token, nil, &c, v, jwt.ParseOptions{}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if c.Subject != "u1" {
			t.Errorf("sub = %q, want u1", c.Subject)
		}
	})

	t.Run("live header, nil claims", func(t *testing.T) {
		h := make(map[string]any)
		if err := jwt.Parse(token, h, nil, v, jwt.ParseOptions{}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if h["alg"] != "HS256" {
			t.Errorf("alg = %v, want HS256", h["alg"])
		}
	})

	// A nil map cannot be filled in place, which is why nil means "I do not
	// need the header" rather than being an error. The token is still verified
	// in full; the caller simply gets nothing back.
	t.Run("a nil map as the header destination", func(t *testing.T) {
		var h map[string]any
		if err := jwt.Parse(token, h, nil, v, jwt.ParseOptions{}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if h != nil {
			t.Errorf("a nil map came back as %v, want it left alone", h)
		}

		forged := token[:len(token)-4] + "AAAA"
		if err := jwt.Parse(forged, h, nil, v, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrSignatureInvalid) {
			t.Fatal("a forged token passed while the header was not wanted")
		}
	})

	t.Run("a nil pointer as the claims destination", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Parse() panicked on a typed nil: %v", r)
			}
		}()

		var c *jwt.RegisteredClaims
		if err := jwt.Parse(token, nil, c, v, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})
}
