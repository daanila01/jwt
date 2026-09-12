package jwt_test

import (
	"strings"
	"testing"

	"github.com/daanila01/jwt"
)

// Fuzzing answers a question a table cannot: is there any input at all that
// makes the parser die rather than refuse?
//
// Returning an error is a pass. Only a panic, a hang, or an outright wrong
// answer counts as a failure, so the checks below assert the two things that
// must never happen: a token nobody signed must not verify, and nothing must
// crash on the way to saying no.
//
// Run it with:
//
//	go test -run '^$' -fuzz FuzzParse -fuzztime 30s
//
// Inputs that break it are written to testdata/fuzz and become ordinary test
// cases from then on, so a bug found once is checked forever.
func FuzzParse(f *testing.F) {
	signer, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatalf("NewHS256() error = %v", err)
	}

	valid, err := jwt.Sign(nil, &jwt.RegisteredClaims{
		Subject:    "u1",
		Issuer:     "auth",
		Audience:   jwt.Audience{"api"},
		Expiration: 4_102_444_800, // well into the future
	}, signer)
	if err != nil {
		f.Fatalf("Sign() error = %v", err)
	}

	// Seeds: one real token and then every shape that has ever gone wrong here,
	// so the mutator starts from interesting bytes rather than from noise.
	seeds := []string{
		valid,
		"",
		".",
		"..",
		"a.b.c",
		"a.b.c.d",
		strings.Repeat("A", 1000),
		signHS256(f, `{"alg":"HS256"}`, `{}`),
		signHS256(f, `{"alg":"none"}`, `{}`),
		signHS256(f, `null`, `{}`),
		signHS256(f, `{"alg":"HS256"}`, `null`),
		signHS256(f, `{"alg":"HS256"}`, `[]`),
		signHS256(f, `{"alg":"HS256"}`, `{"aud":42}`),
		signHS256(f, `{"alg":"HS256"}`, `{"exp":"soon"}`),
		signHS256(f, `{"alg":"HS256"}`, `{"exp":1e309}`),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		var (
			header map[string]any
			claims jwt.RegisteredClaims
		)

		// Every option on, so the fuzzer reaches the validation paths too.
		err := jwt.Parse(token, &header, &claims, signer, jwt.ParseOptions{
			ExpirationValidation: true,
			NotBeforeValidation:  true,
			ExpectedIssuer:       "auth",
			ExpectedAudience:     "api",
		})
		if err == nil && token != valid {
			t.Errorf("a token nobody signed was accepted: %q", token)
		}

		// The same input with nothing to decode into must behave the same way:
		// a refusal is a refusal whether or not anyone wanted the claims.
		if err2 := jwt.Parse(token, nil, nil, signer, jwt.ParseOptions{}); err == nil && err2 != nil {
			t.Errorf("accepted with destinations and refused without: %v", err2)
		}
	})
}

// FuzzParseHeaderOnly narrows the search to the header, which is the half read
// before the signature is checked and therefore the half an attacker reaches
// first.
func FuzzParseHeaderOnly(f *testing.F) {
	signer, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatalf("NewHS256() error = %v", err)
	}

	for _, h := range []string{
		`{"alg":"HS256"}`,
		`{"alg":"HS256","typ":"JWT","kid":"1"}`,
		`{"alg":""}`,
		`{"alg":42}`,
		`{"alg":["HS256"]}`,
		`{}`,
		`null`,
		`[]`,
		`{"alg":"HS256"} trailing`,
		`{"alg":`,
	} {
		f.Add(h)
	}

	f.Fuzz(func(t *testing.T, header string) {
		token := signSegments(t,
			encodeSegment(header),
			encodeSegment(`{"sub":"u1"}`),
		)

		var out map[string]any
		if err := jwt.Parse(token, &out, nil, signer, jwt.ParseOptions{}); err == nil {
			// Accepting is only correct when the header really did name our
			// algorithm; anything else means the check was bypassed.
			if got, _ := out["alg"].(string); got != jwt.AlgorithmHS256 {
				t.Errorf("accepted a token whose alg is %v: header %q", out["alg"], header)
			}
		}
	})
}
