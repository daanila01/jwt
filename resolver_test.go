package jwt_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/daanila01/jwt"
)

// A service that verifies tokens it did not issue holds several keys at once,
// because its issuer publishes the next one before retiring the last. The kid
// in the header is what tells them apart, and ResolveVerifier is where that
// lookup goes.
func TestResolveVerifier(t *testing.T) {
	current, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}
	retired, err := jwt.NewHS256([]byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	keys := map[string]jwt.Verifier{"2024-06": retired, "2024-07": current}
	byKeyID := func(h map[string]any) (jwt.Verifier, error) {
		kid, _ := h["kid"].(string)
		v, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key %q", kid)
		}
		return v, nil
	}

	sign := func(t *testing.T, kid string, signer jwt.Signer) string {
		t.Helper()
		token, err := jwt.Sign(map[string]any{"kid": kid}, &jwt.RegisteredClaims{Subject: "u1"}, signer)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		return token
	}

	t.Run("picks the current key", func(t *testing.T) {
		var c jwt.RegisteredClaims
		err := jwt.Parse(sign(t, "2024-07", current), nil, &c, nil, jwt.ParseOptions{
			ResolveVerifier: byKeyID,
		})
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if c.Subject != "u1" {
			t.Errorf("sub = %q, want u1", c.Subject)
		}
	})

	t.Run("still accepts one signed by the retired key", func(t *testing.T) {
		if err := jwt.Parse(sign(t, "2024-06", retired), nil, nil, nil, jwt.ParseOptions{
			ResolveVerifier: byKeyID,
		}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
	})

	t.Run("a kid that is not ours", func(t *testing.T) {
		if err := jwt.Parse(sign(t, "someone-else", current), nil, nil, nil, jwt.ParseOptions{
			ResolveVerifier: byKeyID,
		}); !errors.Is(err, jwt.ErrTokenInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrTokenInvalid)
		}
	})

	t.Run("the right kid but the wrong key signed it", func(t *testing.T) {
		// Naming one key while being signed by another is the forgery this
		// lookup has to catch, and it is the signature that catches it.
		if err := jwt.Parse(sign(t, "2024-06", current), nil, nil, nil, jwt.ParseOptions{
			ResolveVerifier: byKeyID,
		}); !errors.Is(err, jwt.ErrSignatureInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrSignatureInvalid)
		}
	})

	t.Run("the resolver wins over the argument", func(t *testing.T) {
		if err := jwt.Parse(sign(t, "2024-07", current), nil, nil, retired, jwt.ParseOptions{
			ResolveVerifier: byKeyID,
		}); err != nil {
			t.Fatalf("Parse() error = %v, want the resolver's key to be used", err)
		}
	})

	t.Run("a resolver that returns nothing", func(t *testing.T) {
		if err := jwt.Parse(sign(t, "2024-07", current), nil, nil, nil, jwt.ParseOptions{
			ResolveVerifier: func(map[string]any) (jwt.Verifier, error) { return nil, nil },
		}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("neither a verifier nor a resolver", func(t *testing.T) {
		if err := jwt.Parse(sign(t, "2024-07", current), nil, nil, nil, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})
}

// TestResolverStillPinsTheAlgorithm is the point of resolving before comparing.
// A resolver may hand back a key for any algorithm; the header still has to
// agree with it, so a re-labelled token is refused no matter which key was
// chosen.
func TestResolverStillPinsTheAlgorithm(t *testing.T) {
	hs, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	// Signed with HS256, then read by a resolver that offers an HS384 verifier.
	token, err := jwt.Sign(map[string]any{"kid": "1"}, &jwt.RegisteredClaims{Subject: "u1"}, hs)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	hs384, err := jwt.NewHS384([]byte("0123456789abcdef0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS384() error = %v", err)
	}

	err = jwt.Parse(token, nil, nil, nil, jwt.ParseOptions{
		ResolveVerifier: func(map[string]any) (jwt.Verifier, error) { return hs384, nil },
	})
	if !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("Parse() error = %v, want the algorithm mismatch to be caught", err)
	}
}
