package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// testClaims stands in for what a caller of this package writes: their own type,
// with the registered set embedded when they want the standard fields.
//
// Headers have no matching type. They are a small, flat, string-keyed thing, so
// the package takes a map and a test builds one the way an application would.
type testClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id,omitempty"`
}

// testSigner is the signer used by every case that does not bring its own.
func testSigner(t testing.TB) *jwt.HMAC {
	t.Helper()

	s, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	return s
}

// signHS256 builds a token from raw header and payload text, signed with the
// test key, so that a test can produce shapes Sign itself would never emit.
func signHS256(t testing.TB, header, payload string) string {
	t.Helper()

	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))

	sig, err := testSigner(t).Sign([]byte(h + "." + p))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signSegments signs the two segments exactly as given, without encoding them,
// so that a test can produce a token whose signature is valid over a segment
// that is not valid base64url.
func signSegments(t testing.TB, header, payload string) string {
	t.Helper()

	sig, err := testSigner(t).Sign([]byte(header + "." + payload))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const testHeaderJSON = `{"typ":"JWT","alg":"HS256"}`

// encodeSegment is the base64url a token segment uses: no padding, URL alphabet.
func encodeSegment(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func TestRoundTrip(t *testing.T) {
	// One pair per asymmetric family, so that the custom-struct path is not
	// only ever exercised with HMAC. The per-algorithm tests cover the
	// algorithms themselves; what is unique here is a caller's own type with
	// fields of its own on either side of the round trip.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	edSigner, err := jwt.NewEdDSASigner(edPriv)
	if err != nil {
		t.Fatalf("NewEdDSASigner() error = %v", err)
	}
	edVerifier, err := jwt.NewEdDSAVerifier(edPub)
	if err != nil {
		t.Fatalf("NewEdDSAVerifier() error = %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	ecSigner, err := jwt.NewES256Signer(ecKey)
	if err != nil {
		t.Fatalf("NewES256Signer() error = %v", err)
	}
	ecVerifier, err := jwt.NewES256Verifier(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("NewES256Verifier() error = %v", err)
	}

	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name string

		// A nil header is passed through as a literal nil, which the package
		// treats as "build one for me".
		header map[string]any
		claims *testClaims

		parseOptions jwt.ParseOptions

		// Left nil, these fall back to testSigner.
		signer   jwt.Signer
		verifier jwt.Verifier

		wantSignErr  error
		wantParseErr error
	}{
		{
			name:   "signs and parses a token",
			claims: &testClaims{UserID: "u1"},
		},
		{
			name:   "carries a full claims set and a header of its own",
			header: map[string]any{"kid": "2024-06", "svc": "billing"},
			claims: &testClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ID:         "01J8Z5R2QK9V3T6M",
					Issuer:     "auth.example.com",
					Subject:    "6f1c8a52-4e7b-4a2f-9f7e-2b0d6a1c9e84",
					Audience:   jwt.Audience{"api.example.com", "billing.example.com"},
					Expiration: now.Add(time.Hour).Unix(),
					NotBefore:  now.Add(-time.Minute).Unix(),
					IssuedAt:   now.Unix(),
				},
				UserID: "6f1c8a52-4e7b-4a2f-9f7e-2b0d6a1c9e84",
			},
			parseOptions: jwt.ParseOptions{
				ExpirationValidation: true,
				NotBeforeValidation:  true,
				ExpectedIssuer:       "auth.example.com",
				ExpectedAudience:     "api.example.com",
				Time:                 now,
				ClockSkew:            30 * time.Second,
			},
		},
		{
			name:     "signs and parses with EdDSA",
			claims:   &testClaims{UserID: "u1"},
			signer:   edSigner,
			verifier: edVerifier,
		},
		{
			name:     "signs and parses with ES256",
			header:   map[string]any{"kid": "2024-06"},
			claims:   &testClaims{UserID: "u1"},
			signer:   ecSigner,
			verifier: ecVerifier,
		},
		{
			name:         "a verifier for another algorithm is refused",
			claims:       &testClaims{UserID: "u1"},
			signer:       edSigner,
			verifier:     nil, // falls back to HMAC
			wantParseErr: jwt.ErrTokenInvalid,
		},
		{
			name:        "rejects nil claims",
			wantSignErr: jwt.ErrArgumentInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, verifier := tt.signer, tt.verifier
			if signer == nil || verifier == nil {
				hs := testSigner(t)
				if signer == nil {
					signer = hs
				}
				if verifier == nil {
					verifier = hs
				}
			}

			// Copies, so that Sign writing alg into the header and the table
			// being reused do not interfere.
			var inHeader map[string]any
			if tt.header != nil {
				inHeader = maps.Clone(tt.header)
			}
			var inClaims *testClaims
			if tt.claims != nil {
				c := *tt.claims
				inClaims = &c
			}

			// Passing a nil *testClaims is not the same as passing nil: the
			// interface would carry a type. Hence the branch.
			var (
				token string
				err   error
			)
			if inClaims != nil {
				token, err = jwt.Sign(inHeader, inClaims, signer)
			} else {
				token, err = jwt.Sign(inHeader, nil, signer)
			}

			if !errors.Is(err, tt.wantSignErr) {
				t.Fatalf("Sign() error = %v, want %v", err, tt.wantSignErr)
			}
			if tt.wantSignErr != nil {
				return
			}
			if token == "" {
				t.Fatal("Sign() returned an empty token")
			}

			// Parsing into nothing still verifies the token in full.
			if err := jwt.Parse(token, nil, nil, verifier, tt.parseOptions); !errors.Is(err, tt.wantParseErr) {
				t.Fatalf("Parse() with nil destinations error = %v, want %v", err, tt.wantParseErr)
			}

			outHeader := make(map[string]any)
			var outClaims testClaims
			if err := jwt.Parse(token, &outHeader, &outClaims, verifier, tt.parseOptions); !errors.Is(err, tt.wantParseErr) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.wantParseErr)
			}
			if tt.wantParseErr != nil {
				return
			}

			if got := outHeader["alg"]; got != signer.Algorithm() {
				t.Errorf("header alg = %v, want %q", got, signer.Algorithm())
			}
			for k, want := range inHeader {
				if k == "alg" {
					continue // written by Sign, checked above
				}
				if got := outHeader[k]; got != want {
					t.Errorf("header %q = %v, want %v", k, got, want)
				}
			}

			if inClaims != nil {
				if outClaims.UserID != inClaims.UserID {
					t.Errorf("claim user_id = %q, want %q", outClaims.UserID, inClaims.UserID)
				}
				if outClaims.ID != inClaims.ID {
					t.Errorf("claim jti = %q, want %q", outClaims.ID, inClaims.ID)
				}
				if !slices.Equal(outClaims.Audience, inClaims.Audience) {
					t.Errorf("claim aud = %v, want %v", outClaims.Audience, inClaims.Audience)
				}
				if outClaims.Issuer != inClaims.Issuer {
					t.Errorf("claim iss = %q, want %q", outClaims.Issuer, inClaims.Issuer)
				}
				if outClaims.Subject != inClaims.Subject {
					t.Errorf("claim sub = %q, want %q", outClaims.Subject, inClaims.Subject)
				}
				if outClaims.Expiration != inClaims.Expiration {
					t.Errorf("claim exp = %d, want %d", outClaims.Expiration, inClaims.Expiration)
				}
				if outClaims.NotBefore != inClaims.NotBefore {
					t.Errorf("claim nbf = %d, want %d", outClaims.NotBefore, inClaims.NotBefore)
				}
				if outClaims.IssuedAt != inClaims.IssuedAt {
					t.Errorf("claim iat = %d, want %d", outClaims.IssuedAt, inClaims.IssuedAt)
				}
			}
		})
	}
}

// TestRegisteredClaimsSetters covers the helpers that keep a caller from having
// to convert time themselves, which is where seconds and milliseconds get
// confused.
func TestRegisteredClaimsSetters(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)

	var c jwt.RegisteredClaims
	c.SetID("jti-1")
	c.SetIssuer("auth")
	c.SetSubject("u1")
	c.SetAudience(jwt.Audience{"api"})
	c.SetExpiration(at.Add(time.Hour))
	c.SetNotBefore(at)
	c.SetIssuedAt(at)

	if c.ID != "jti-1" || c.Issuer != "auth" || c.Subject != "u1" {
		t.Errorf("string claims not set: %+v", c)
	}
	if !slices.Equal(c.Audience, jwt.Audience{"api"}) {
		t.Errorf("aud = %v", c.Audience)
	}
	if c.Expiration != at.Add(time.Hour).Unix() {
		t.Errorf("exp = %d, want %d", c.Expiration, at.Add(time.Hour).Unix())
	}
	if c.NotBefore != at.Unix() || c.IssuedAt != at.Unix() {
		t.Errorf("nbf = %d, iat = %d, want %d for both", c.NotBefore, c.IssuedAt, at.Unix())
	}
}
