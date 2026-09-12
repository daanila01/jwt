package jwt_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// TestParseRejects covers everything Parse must refuse. Each case names the
// sentinel a caller would match on, because that is the part of the contract
// applications depend on: malformed input answers differently from a forged
// token, which answers differently from an expired one.
func TestParseRejects(t *testing.T) {
	valid := signHS256(t, testHeaderJSON, `{"sub":"u1"}`)

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty string", "", jwt.ErrTokenInvalid},
		{"no separators", "abc", jwt.ErrTokenInvalid},
		{"two segments", "aa.bb", jwt.ErrTokenInvalid},
		{"four segments", "aa.bb.cc.dd", jwt.ErrTokenInvalid},
		{"empty header segment", "." + strings.Join(strings.Split(valid, ".")[1:], "."), jwt.ErrTokenInvalid},
		{"empty payload segment", strings.Split(valid, ".")[0] + ".." + strings.Split(valid, ".")[2], jwt.ErrTokenInvalid},
		{"empty signature segment", strings.Join(strings.Split(valid, ".")[:2], ".") + ".", jwt.ErrTokenInvalid},
		{"header is not base64url", signSegments(t, "!!!", base64.RawURLEncoding.EncodeToString([]byte(`{}`))), jwt.ErrTokenInvalid},
		{"header uses standard base64 alphabet", "e30+." + strings.Join(strings.Split(valid, ".")[1:], "."), jwt.ErrTokenInvalid},
		{"header is null", signHS256(t, `null`, `{}`), jwt.ErrTokenInvalid},
		{"header is an array", signHS256(t, `["HS256"]`, `{}`), jwt.ErrTokenInvalid},
		{"header is a string", signHS256(t, `"HS256"`, `{}`), jwt.ErrTokenInvalid},
		{"header is a number", signHS256(t, `256`, `{}`), jwt.ErrTokenInvalid},
		{"header is broken json", signHS256(t, `{"alg":`, `{}`), jwt.ErrTokenInvalid},
		{"header has trailing data", signHS256(t, `{"alg":"HS256"} junk`, `{}`), jwt.ErrTokenInvalid},
		{"alg is absent", signHS256(t, `{"typ":"JWT"}`, `{}`), jwt.ErrTokenInvalid},
		{"alg is an empty string", signHS256(t, `{"typ":"JWT","alg":""}`, `{}`), jwt.ErrTokenInvalid},
		{"alg is none", signHS256(t, `{"typ":"JWT","alg":"none"}`, `{}`), jwt.ErrTokenInvalid},
		{"alg is another algorithm", signHS256(t, `{"typ":"JWT","alg":"RS256"}`, `{}`), jwt.ErrTokenInvalid},
		{"alg is a number", signHS256(t, `{"typ":"JWT","alg":256}`, `{}`), jwt.ErrTokenInvalid},
		{"payload is null", signHS256(t, testHeaderJSON, `null`), jwt.ErrTokenInvalid},
		{"payload is null with spaces", signHS256(t, testHeaderJSON, ` null `), jwt.ErrTokenInvalid},
		{"payload is an array", signHS256(t, testHeaderJSON, `[]`), jwt.ErrTokenInvalid},
		{"payload is broken json", signHS256(t, testHeaderJSON, `{"sub":`), jwt.ErrTokenInvalid},
		{"payload has trailing data", signHS256(t, testHeaderJSON, `{} junk`), jwt.ErrTokenInvalid},
		// Signed over the broken segment on purpose: otherwise the signature
		// check would reject it first and the decode below would be unreachable.
		{"payload is not base64url", signSegments(t, base64.RawURLEncoding.EncodeToString([]byte(testHeaderJSON)), "!!!"), jwt.ErrTokenInvalid},
		{"signature is not base64url", strings.Join(strings.Split(valid, ".")[:2], ".") + ".!!!", jwt.ErrTokenInvalid},
	}

	v := testSigner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c jwt.RegisteredClaims
			if err := jwt.Parse(tt.token, nil, &c, v, jwt.ParseOptions{}); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestParseRejectsForgery covers the cases where the token is well formed but
// not authentic. These answer with ErrSignatureInvalid rather than
// ErrTokenInvalid, so that a caller can log a forgery and a typo differently.
func TestParseRejectsForgery(t *testing.T) {
	v := testSigner(t)
	valid := signHS256(t, testHeaderJSON, `{"sub":"u1"}`)
	parts := strings.Split(valid, ".")

	other, err := jwt.NewHS256([]byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}
	otherKey, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, other)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	tampered := parts[0] + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + "." + parts[2]

	flipped := []byte(parts[2])
	flipped[0] ^= 0x01
	if string(flipped) == parts[2] {
		t.Fatal("flipping the signature changed nothing")
	}

	tests := []struct {
		name  string
		token string
	}{
		{"payload swapped under an unchanged signature", tampered},
		{"signature altered", parts[0] + "." + parts[1] + "." + string(flipped)},
		{"signature replaced by garbage of the right length", parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))},
		{"signature truncated", parts[0] + "." + parts[1] + "." + parts[2][:40]},
		{"signed with a different key", otherKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c jwt.RegisteredClaims
			if err := jwt.Parse(tt.token, nil, &c, v, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrSignatureInvalid) {
				t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrSignatureInvalid)
			}
		})
	}
}

// TestParseArguments covers what Parse does before it looks at the token.
func TestParseArguments(t *testing.T) {
	v := testSigner(t)
	valid := signHS256(t, testHeaderJSON, `{"sub":"u1"}`)

	t.Run("nil verifier", func(t *testing.T) {
		var c jwt.RegisteredClaims
		if err := jwt.Parse(valid, nil, &c, nil, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrArgumentInvalid) {
			t.Fatalf("Parse() error = %v, want %v", err, jwt.ErrArgumentInvalid)
		}
	})

	t.Run("nil destinations still verify", func(t *testing.T) {
		if err := jwt.Parse(valid, nil, nil, v, jwt.ParseOptions{}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if err := jwt.Parse(valid[:len(valid)-4]+"AAAA", nil, nil, v, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrSignatureInvalid) {
			t.Fatal("a forged token passed while parsing into nothing")
		}
	})

	t.Run("size limit", func(t *testing.T) {
		if err := jwt.Parse(valid, nil, nil, v, jwt.ParseOptions{MaxTokenSize: len(valid) - 1}); !errors.Is(err, jwt.ErrTokenInvalid) {
			t.Fatal("a token past the limit was accepted")
		}
		if err := jwt.Parse(valid, nil, nil, v, jwt.ParseOptions{MaxTokenSize: len(valid)}); err != nil {
			t.Fatalf("a token exactly at the limit was rejected: %v", err)
		}
	})

	t.Run("does not clear the destination", func(t *testing.T) {
		// Documented behaviour: encoding/json merges, so a field the new token
		// omits keeps whatever the previous one left there.
		c := jwt.RegisteredClaims{Subject: "stale", Issuer: "stale"}
		if err := jwt.Parse(signHS256(t, testHeaderJSON, `{"iss":"fresh"}`), nil, &c, v, jwt.ParseOptions{}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if c.Issuer != "fresh" {
			t.Errorf("iss = %q, want %q", c.Issuer, "fresh")
		}
		if c.Subject != "stale" {
			t.Errorf("sub = %q, want %q: Parse is documented not to clear the destination", c.Subject, "stale")
		}
	})
}

// TestParseTimeClaims covers exp and nbf, including the boundary moments where
// the two are deliberately not symmetric: exp is invalid at the instant itself,
// nbf is valid at it.
func TestParseTimeClaims(t *testing.T) {
	v := testSigner(t)
	now := time.Unix(1_700_000_000, 0)

	token := func(payload string) string { return signHS256(t, testHeaderJSON, payload) }

	tests := []struct {
		name  string
		token string
		opts  jwt.ParseOptions
		want  error
	}{
		{
			name:  "exp in the future",
			token: token(`{"exp":1700000060}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now},
		},
		{
			name:  "exp in the past",
			token: token(`{"exp":1699999940}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now},
			want:  jwt.ErrExpired,
		},
		{
			name:  "exp at this very second is already expired",
			token: token(`{"exp":1700000000}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now},
			want:  jwt.ErrExpired,
		},
		{
			name:  "exp absent while checking it",
			token: token(`{"sub":"u1"}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now},
			want:  jwt.ErrClaimMissing,
		},
		{
			name:  "exp absent without checking it",
			token: token(`{"sub":"u1"}`),
			opts:  jwt.ParseOptions{Time: now},
		},
		{
			name:  "skew keeps a just expired token alive",
			token: token(`{"exp":1699999990}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now, ClockSkew: 30 * time.Second},
		},
		{
			name:  "skew does not reach far enough",
			token: token(`{"exp":1699999940}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now, ClockSkew: 30 * time.Second},
			want:  jwt.ErrExpired,
		},
		{
			name:  "nbf in the past",
			token: token(`{"nbf":1699999940}`),
			opts:  jwt.ParseOptions{NotBeforeValidation: true, Time: now},
		},
		{
			name:  "nbf in the future",
			token: token(`{"nbf":1700000060}`),
			opts:  jwt.ParseOptions{NotBeforeValidation: true, Time: now},
			want:  jwt.ErrNotYetValid,
		},
		{
			name:  "nbf at this very second is already valid",
			token: token(`{"nbf":1700000000}`),
			opts:  jwt.ParseOptions{NotBeforeValidation: true, Time: now},
		},
		{
			name:  "nbf absent while checking it",
			token: token(`{"sub":"u1"}`),
			opts:  jwt.ParseOptions{NotBeforeValidation: true, Time: now},
			want:  jwt.ErrClaimMissing,
		},
		{
			name:  "skew lets a token start a little early",
			token: token(`{"nbf":1700000010}`),
			opts:  jwt.ParseOptions{NotBeforeValidation: true, Time: now, ClockSkew: 30 * time.Second},
		},
		{
			name:  "negative skew tightens instead of loosening",
			token: token(`{"exp":1700000010}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, Time: now, ClockSkew: -30 * time.Second},
			want:  jwt.ErrExpired,
		},
		{
			name:  "exp and nbf checked together",
			token: token(`{"nbf":1699999940,"exp":1700000060}`),
			opts:  jwt.ParseOptions{ExpirationValidation: true, NotBeforeValidation: true, Time: now},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c jwt.RegisteredClaims
			if err := jwt.Parse(tt.token, nil, &c, v, tt.opts); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestParseIssuerAndAudience covers the two checks that are switched on by a
// non-empty expectation rather than by a flag.
func TestParseIssuerAndAudience(t *testing.T) {
	v := testSigner(t)
	token := func(payload string) string { return signHS256(t, testHeaderJSON, payload) }

	tests := []struct {
		name  string
		token string
		opts  jwt.ParseOptions
		want  error
	}{
		{
			name:  "issuer matches",
			token: token(`{"iss":"auth.example.com"}`),
			opts:  jwt.ParseOptions{ExpectedIssuer: "auth.example.com"},
		},
		{
			name:  "issuer differs",
			token: token(`{"iss":"evil.example.com"}`),
			opts:  jwt.ParseOptions{ExpectedIssuer: "auth.example.com"},
			want:  jwt.ErrTokenInvalid,
		},
		{
			name:  "issuer differs only by case",
			token: token(`{"iss":"Auth.Example.com"}`),
			opts:  jwt.ParseOptions{ExpectedIssuer: "auth.example.com"},
			want:  jwt.ErrTokenInvalid,
		},
		{
			name:  "issuer absent while expecting one",
			token: token(`{"sub":"u1"}`),
			opts:  jwt.ParseOptions{ExpectedIssuer: "auth.example.com"},
			want:  jwt.ErrTokenInvalid,
		},
		{
			name:  "issuer present, none expected",
			token: token(`{"iss":"anyone"}`),
			opts:  jwt.ParseOptions{},
		},
		{
			name:  "audience as an array containing us",
			token: token(`{"aud":["billing","api"]}`),
			opts:  jwt.ParseOptions{ExpectedAudience: "api"},
		},
		{
			name:  "audience as a bare string equal to us",
			token: token(`{"aud":"api"}`),
			opts:  jwt.ParseOptions{ExpectedAudience: "api"},
		},
		{
			name:  "audience does not name us",
			token: token(`{"aud":["billing"]}`),
			opts:  jwt.ParseOptions{ExpectedAudience: "api"},
			want:  jwt.ErrTokenInvalid,
		},
		{
			name:  "audience absent while expecting one",
			token: token(`{"sub":"u1"}`),
			opts:  jwt.ParseOptions{ExpectedAudience: "api"},
			want:  jwt.ErrTokenInvalid,
		},
		{
			name:  "audience present, none expected",
			token: token(`{"aud":["someone-else"]}`),
			opts:  jwt.ParseOptions{},
		},
		{
			name:  "audience of the wrong type",
			token: token(`{"aud":42}`),
			opts:  jwt.ParseOptions{ExpectedAudience: "api"},
			want:  jwt.ErrTokenInvalid,
		},
		{
			name:  "issuer and audience together",
			token: token(`{"iss":"auth","aud":"api"}`),
			opts:  jwt.ParseOptions{ExpectedIssuer: "auth", ExpectedAudience: "api"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c jwt.RegisteredClaims
			if err := jwt.Parse(tt.token, nil, &c, v, tt.opts); !errors.Is(err, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}
