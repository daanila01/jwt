package jwt_test

import (
	"testing"

	"github.com/daanila01/jwt"
)

// A nil pointer to the caller's own type panics instead of returning an error.
//
// An interface holding a typed nil is not equal to nil, so the guard in Sign and
// Parse does not see it, and the promoted method dereferences the pointer before
// this package gets a chance to look. Catching it needs reflect, which has not
// been added yet.
//
// These tests pin the current behaviour rather than the wanted one. When the gap
// is closed they will fail, which is the point: the failure is the reminder to
// replace them with the assertion that an error comes back.
//
// It is worth closing. The first table-driven test written against this package
// hit it immediately, because leaving a pointer field unset in a table is the
// natural thing to do, and a panic raised inside a library reads to its user as
// a bug in the library.

type gapClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id,omitempty"`
}

type gapHeaders struct {
	jwt.RegisteredHeaders
}

func TestKnownGapTypedNilClaimsPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Sign() no longer panics on a typed nil: close this gap for real and assert ErrArgumentInvalid instead")
		}
	}()

	var c *gapClaims
	_, _ = jwt.Sign(nil, c, testSigner(t), jwt.SignOptions{})
}

func TestKnownGapTypedNilHeadersPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Sign() no longer panics on a typed nil: close this gap for real and assert ErrArgumentInvalid instead")
		}
	}()

	var h *gapHeaders
	_, _ = jwt.Sign(h, &jwt.RegisteredClaims{}, testSigner(t), jwt.SignOptions{})
}

func TestKnownGapTypedNilOnParsePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Parse() no longer panics on a typed nil: close this gap for real and assert an error instead")
		}
	}()

	token := signHS256(t, testHeaderJSON, `{"sub":"u1"}`)

	var c *gapClaims
	_ = jwt.Parse(token, nil, c, testSigner(t), jwt.ParseOptions{})
}
