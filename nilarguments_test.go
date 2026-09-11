package jwt_test

import (
	"errors"
	"testing"

	"github.com/daanila01/jwt"
)

// A nil that arrives inside an interface used to panic here.
//
// An interface holding a typed nil is not equal to nil, so a plain == nil check
// misses it, and the method promoted from an embedded field dereferences the
// pointer before this package can look at it. Every shape below now answers
// with an error instead.
//
// The tests fail on a panic rather than recovering from one: a library that
// panics on a caller's mistake reads to that caller as a library bug.

type nilEmbedValue struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id,omitempty"`
}

type nilEmbedPointer struct {
	*jwt.RegisteredClaims
	UserID string `json:"user_id,omitempty"`
}

type nilHeaderEmbedValue struct {
	jwt.RegisteredHeaders
}

type nilHeaderEmbedPointer struct {
	*jwt.RegisteredHeaders
}

func TestSignRejectsEveryShapeOfNilClaims(t *testing.T) {
	s := testSigner(t)

	var (
		registered   *jwt.RegisteredClaims
		embedValue   *nilEmbedValue
		embedPointer *nilEmbedPointer
	)

	tests := []struct {
		name   string
		claims func() (string, error)
	}{
		{"literal nil", func() (string, error) {
			return jwt.Sign(nil, nil, s, jwt.SignOptions{})
		}},
		{"nil pointer to the registered set", func() (string, error) {
			return jwt.Sign(nil, registered, s, jwt.SignOptions{})
		}},
		{"nil pointer to a type embedding it by value", func() (string, error) {
			return jwt.Sign(nil, embedValue, s, jwt.SignOptions{})
		}},
		{"nil pointer to a type embedding it by pointer", func() (string, error) {
			return jwt.Sign(nil, embedPointer, s, jwt.SignOptions{})
		}},
		{"live outer, nil embedded pointer", func() (string, error) {
			return jwt.Sign(nil, &nilEmbedPointer{UserID: "u1"}, s, jwt.SignOptions{})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Sign() panicked instead of returning an error: %v", r)
				}
			}()

			if _, err := tt.claims(); !errors.Is(err, jwt.ErrArgumentInvalid) {
				t.Fatalf("Sign() error = %v, want %v", err, jwt.ErrArgumentInvalid)
			}
		})
	}
}

func TestSignRejectsEveryShapeOfNilHeaders(t *testing.T) {
	s := testSigner(t)
	c := &jwt.RegisteredClaims{Subject: "u1"}

	var (
		registered   *jwt.RegisteredHeaders
		embedValue   *nilHeaderEmbedValue
		embedPointer *nilHeaderEmbedPointer
	)

	tests := []struct {
		name string
		sign func() (string, error)
		want error
	}{
		// A literal nil means "no header of my own", which is a request, not a
		// mistake, so it is filled in rather than refused.
		{"literal nil is filled in", func() (string, error) {
			return jwt.Sign(nil, c, s, jwt.SignOptions{})
		}, nil},
		{"nil pointer to the registered set", func() (string, error) {
			return jwt.Sign(registered, c, s, jwt.SignOptions{})
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to a type embedding it by value", func() (string, error) {
			return jwt.Sign(embedValue, c, s, jwt.SignOptions{})
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to a type embedding it by pointer", func() (string, error) {
			return jwt.Sign(embedPointer, c, s, jwt.SignOptions{})
		}, jwt.ErrArgumentInvalid},
		{"live outer, nil embedded pointer", func() (string, error) {
			return jwt.Sign(&nilHeaderEmbedPointer{}, c, s, jwt.SignOptions{})
		}, jwt.ErrArgumentInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Sign() panicked instead of returning an error: %v", r)
				}
			}()

			if _, err := tt.sign(); !errors.Is(err, tt.want) {
				t.Fatalf("Sign() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseRejectsEveryShapeOfNilDestination(t *testing.T) {
	v := testSigner(t)
	token := signHS256(t, testHeaderJSON, `{"sub":"u1"}`)

	var (
		claims       *jwt.RegisteredClaims
		headers      *jwt.RegisteredHeaders
		embedValue   *nilEmbedValue
		embedPointer *nilEmbedPointer
	)

	tests := []struct {
		name  string
		parse func() error
		want  error
	}{
		// Both nil means "verify it, I want nothing back", which is allowed.
		{"literal nils are filled in", func() error {
			return jwt.Parse(token, nil, nil, v, jwt.ParseOptions{})
		}, nil},
		{"nil pointer to the registered claims", func() error {
			return jwt.Parse(token, nil, claims, v, jwt.ParseOptions{})
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to the registered headers", func() error {
			return jwt.Parse(token, headers, nil, v, jwt.ParseOptions{})
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to a type embedding by value", func() error {
			return jwt.Parse(token, nil, embedValue, v, jwt.ParseOptions{})
		}, jwt.ErrArgumentInvalid},
		{"nil pointer to a type embedding by pointer", func() error {
			return jwt.Parse(token, nil, embedPointer, v, jwt.ParseOptions{})
		}, jwt.ErrArgumentInvalid},
		{"live outer, nil embedded pointer", func() error {
			return jwt.Parse(token, nil, &nilEmbedPointer{}, v, jwt.ParseOptions{})
		}, jwt.ErrArgumentInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse() panicked instead of returning an error: %v", r)
				}
			}()

			if err := tt.parse(); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}
