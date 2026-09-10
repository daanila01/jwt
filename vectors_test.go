package jwt_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// The worked example from RFC 7515, Appendix A.1: a token, and the key that
// signed it, published by the authors of the specification.
//
// This is the only kind of test that proves interoperability. A round trip
// proves the package agrees with itself, which it would even if the base64
// alphabet were wrong in both directions.
const (
	rfc7515A1Key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

	rfc7515A1Token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func rfc7515A1Verifier(t *testing.T) *jwt.HS256 {
	t.Helper()

	key, err := base64.RawURLEncoding.DecodeString(rfc7515A1Key)
	if err != nil {
		t.Fatalf("decoding the reference key: %v", err)
	}

	v, err := jwt.NewHS256(key)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	return v
}

// TestRFC7515A1 verifies the reference token and reads its claims.
//
// The token cannot be reproduced byte for byte: its header carries a literal
// CRLF and a space inside the JSON, and Sign builds its own compact header.
// Verification is the half that matters, and it is the half a library gets
// wrong when its encoding is subtly off.
func TestRFC7515A1(t *testing.T) {
	v := rfc7515A1Verifier(t)

	var (
		h jwt.RegisteredHeaders
		c jwt.RegisteredClaims
	)
	err := jwt.Parse(rfc7515A1Token, &h, &c, v, jwt.ParseOptions{
		ExpirationValidation: true,
		Time:                 time.Unix(1_300_819_379, 0),
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if h.Algorithm != "HS256" {
		t.Errorf("alg = %q, want HS256", h.Algorithm)
	}
	if h.Type != "JWT" {
		t.Errorf("typ = %q, want JWT", h.Type)
	}
	if c.Issuer != "joe" {
		t.Errorf("iss = %q, want joe", c.Issuer)
	}
	if c.Expiration != 1_300_819_380 {
		t.Errorf("exp = %d, want 1300819380", c.Expiration)
	}
}

// TestRFC7515A1Expired uses the same reference token past its expiry, so that
// the vector exercises the failing direction too.
func TestRFC7515A1Expired(t *testing.T) {
	v := rfc7515A1Verifier(t)

	var c jwt.RegisteredClaims
	err := jwt.Parse(rfc7515A1Token, nil, &c, v, jwt.ParseOptions{
		ExpirationValidation: true,
		Time:                 time.Unix(1_300_819_381, 0),
	})
	if err == nil {
		t.Fatal("Parse() accepted a token past its exp")
	}
}

// TestRFC7515A1WrongKey checks the reference token against a different secret.
func TestRFC7515A1WrongKey(t *testing.T) {
	other, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	if err := jwt.Parse(rfc7515A1Token, nil, nil, other, jwt.ParseOptions{}); err == nil {
		t.Fatal("Parse() accepted the reference token under a different key")
	}
}

// TestRFC7515A5Unsecured is the example from Appendix A.5: a token with
// "alg":"none" and an empty signature. The specification allows it and this
// package does not, deliberately, because a library that honours it hands an
// attacker a way to mint any claims at all.
func TestRFC7515A5Unsecured(t *testing.T) {
	const token = "eyJhbGciOiJub25lIn0." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	if err := jwt.Parse(token, nil, nil, rfc7515A1Verifier(t), jwt.ParseOptions{}); err == nil {
		t.Fatal("Parse() accepted an unsecured token")
	}
}

// TestGoldenToken pins the exact bytes this package produces for a fixed input.
// Where the RFC vector proves agreement with the specification, this one proves
// that a refactor did not silently change the encoding: field order, the base64
// alphabet, padding, the separator.
func TestGoldenToken(t *testing.T) {
	const want = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
		"eyJqdGkiOiJ0b2tlbi0xIiwiYXVkIjpbImFwaSJdLCJpc3MiOiJhdXRoIiwic3ViIjoidTEiLCJleHAiOjE3MDAwMDAwNjAsIm5iZiI6MTY5OTk5OTk0MCwiaWF0IjoxNzAwMDAwMDAwfQ." +
		"4h2LXci54KgBX4au9o1W0fOcIlDuvl4oh9SylkfDfr8"

	got, err := jwt.Sign(nil, &jwt.RegisteredClaims{
		ID:       "token-1",
		Audience: jwt.Audience{"api"},
		Issuer:   "auth",
		Subject:  "u1",
	}, testSigner(t), jwt.SignOptions{
		Expiration: time.Unix(1_700_000_060, 0),
		NotBefore:  time.Unix(1_699_999_940, 0),
		IssuedAt:   time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if got != want {
		t.Errorf("the encoding changed.\n got %s\nwant %s", got, want)
	}
}
