package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// testHeaders and testClaims stand in for what a caller of this package writes:
// their own type with the registered set embedded.
type testHeaders struct {
	jwt.RegisteredHeaders
	Service string `json:"svc,omitempty"`
}

type testClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id,omitempty"`
}

// testSigner is the signer used by every case that does not bring its own.
func testSigner(t *testing.T) *jwt.HMAC {
	t.Helper()

	s, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	return s
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

	tests := []struct {
		name string

		// A nil headers or claims is passed to Sign and Parse as a literal nil,
		// which the package treats as "build a throwaway registered set".
		headers *testHeaders
		claims  *testClaims

		signOptions  jwt.SignOptions
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
			name:    "carries a full claims set and a header of its own",
			headers: &testHeaders{Service: "billing"},
			claims: &testClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ID:       "01J8Z5R2QK9V3T6M",
					Issuer:   "auth.example.com",
					Subject:  "6f1c8a52-4e7b-4a2f-9f7e-2b0d6a1c9e84",
					Audience: jwt.Audience{"api.example.com", "billing.example.com"},
				},
				UserID: "6f1c8a52-4e7b-4a2f-9f7e-2b0d6a1c9e84",
			},
			signOptions: jwt.SignOptions{
				Expiration: time.Now().Add(time.Hour),
				NotBefore:  time.Now().Add(-time.Minute),
				IssuedAt:   time.Now(),
			},
			parseOptions: jwt.ParseOptions{
				ExpirationValidation: true,
				NotBeforeValidation:  true,
				ExpectedIssuer:       "auth.example.com",
				ExpectedAudience:     "api.example.com",
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
			headers:  &testHeaders{Service: "billing"},
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

			// Copy, so that Sign writing alg, typ and the time claims does not
			// mutate the table itself.
			var inHeaders *testHeaders
			if tt.headers != nil {
				h := *tt.headers
				inHeaders = &h
			}
			var inClaims *testClaims
			if tt.claims != nil {
				c := *tt.claims
				inClaims = &c
			}

			// The interfaces Sign and Parse take are unexported on purpose, so a
			// test cannot hold a variable of one. Passing a nil *testClaims is
			// not the same as passing nil: the interface would carry a type and
			// compare unequal to nil. Hence the branches.
			var (
				token string
				err   error
			)
			switch {
			case inHeaders != nil && inClaims != nil:
				token, err = jwt.Sign(inHeaders, inClaims, signer, tt.signOptions)
			case inHeaders != nil:
				token, err = jwt.Sign(inHeaders, nil, signer, tt.signOptions)
			case inClaims != nil:
				token, err = jwt.Sign(nil, inClaims, signer, tt.signOptions)
			default:
				token, err = jwt.Sign(nil, nil, signer, tt.signOptions)
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

			var outHeaders testHeaders
			var outClaims testClaims
			if err := jwt.Parse(token, &outHeaders, &outClaims, verifier, tt.parseOptions); !errors.Is(err, tt.wantParseErr) {
				t.Fatalf("Parse() error = %v, want %v", err, tt.wantParseErr)
			}
			if tt.wantParseErr != nil {
				return
			}

			if outHeaders.Algorithm != signer.Algorithm() {
				t.Errorf("header alg = %q, want %q", outHeaders.Algorithm, signer.Algorithm())
			}
			if inHeaders != nil {
				if outHeaders.Service != inHeaders.Service {
					t.Errorf("header svc = %q, want %q", outHeaders.Service, inHeaders.Service)
				}
				if outHeaders.Type != inHeaders.Type {
					t.Errorf("header typ = %q, want %q", outHeaders.Type, inHeaders.Type)
				}
				if outHeaders.KeyID != inHeaders.KeyID {
					t.Errorf("header kid = %q, want %q", outHeaders.KeyID, inHeaders.KeyID)
				}
			}

			// Compared against the options rather than against the input, so a
			// Sign that stopped reading them would not slip through by leaving
			// both sides zero.
			if !tt.signOptions.Expiration.IsZero() && outClaims.Expiration != tt.signOptions.Expiration.Unix() {
				t.Errorf("claim exp = %d, want %d", outClaims.Expiration, tt.signOptions.Expiration.Unix())
			}
			if !tt.signOptions.NotBefore.IsZero() && outClaims.NotBefore != tt.signOptions.NotBefore.Unix() {
				t.Errorf("claim nbf = %d, want %d", outClaims.NotBefore, tt.signOptions.NotBefore.Unix())
			}
			if !tt.signOptions.IssuedAt.IsZero() && outClaims.IssuedAt != tt.signOptions.IssuedAt.Unix() {
				t.Errorf("claim iat = %d, want %d", outClaims.IssuedAt, tt.signOptions.IssuedAt.Unix())
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

// signHS256 builds a token from raw header and payload text, signed with key, so
// that a test can produce shapes Sign itself would never emit.
func signHS256(t *testing.T, header, payload string) string {
	t.Helper()

	s := testSigner(t)
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))

	sig, err := s.Sign([]byte(h + "." + p))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const testHeaderJSON = `{"typ":"JWT","alg":"HS256"}`

// signSegments signs the two segments exactly as given, without encoding them,
// so that a test can produce a token whose signature is valid over a segment
// that is not valid base64url.
func signSegments(t *testing.T, header, payload string) string {
	t.Helper()

	sig, err := testSigner(t).Sign([]byte(header + "." + payload))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
}
