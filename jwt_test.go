package jwt_test

import (
	"encoding/base64"
	"errors"
	"slices"
	"testing"

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
