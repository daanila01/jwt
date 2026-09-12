package jwt_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/daanila01/jwt"
)

// TestAudienceUnmarshal covers both forms RFC 7519 allows on the wire. A single
// recipient is often written as a bare string, which is what Google and Auth0
// emit, so refusing it would reject valid tokens.
func TestAudienceUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    jwt.Audience
		wantErr bool
	}{
		{"array of several", `["api","web"]`, jwt.Audience{"api", "web"}, false},
		{"array of one", `["api"]`, jwt.Audience{"api"}, false},
		{"empty array", `[]`, jwt.Audience{}, false},
		{"bare string", `"api"`, jwt.Audience{"api"}, false},
		{"empty string", `""`, jwt.Audience{""}, false},
		{"null", `null`, nil, false},
		{"number", `42`, nil, true},
		{"object", `{"aud":"api"}`, nil, true},
		{"array holding a number", `["api",42]`, nil, true},
		{"array holding an array", `[["api"]]`, nil, true},
		{"broken json", `["api"`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got jwt.Audience
			err := json.Unmarshal([]byte(tt.json), &got)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Unmarshal() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestAudienceMarshal pins the writing side: always an array, whatever came in.
// Every implementation reads an array, so there is nothing to gain from
// reproducing the bare-string form.
func TestAudienceMarshal(t *testing.T) {
	tests := []struct {
		name string
		aud  jwt.Audience
		want string
	}{
		{"one recipient", jwt.Audience{"api"}, `["api"]`},
		{"several recipients", jwt.Audience{"api", "web"}, `["api","web"]`},
		{"empty", jwt.Audience{}, `[]`},
		{"nil", nil, `null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.aud)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(b) != tt.want {
				t.Errorf("Marshal() = %s, want %s", b, tt.want)
			}
		})
	}
}

// TestAudienceOmittedWhenEmpty checks the claim disappears rather than being
// written as null, which a strict reader on the other side could refuse.
func TestAudienceOmittedWhenEmpty(t *testing.T) {
	s := testSigner(t)

	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, s)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if got := decodeSegment(t, token, 1); got != `{"sub":"u1"}` {
		t.Errorf("payload = %s, want no aud at all", got)
	}
}

// TestAudienceNormalizesOnParse checks that the two wire forms are
// indistinguishable by the time an application sees them.
func TestAudienceNormalizesOnParse(t *testing.T) {
	v := testSigner(t)

	for _, form := range []string{`{"aud":"api"}`, `{"aud":["api"]}`} {
		t.Run(form, func(t *testing.T) {
			var c jwt.RegisteredClaims
			if err := jwt.Parse(signHS256(t, testHeaderJSON, form), nil, &c, v, jwt.ParseOptions{}); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !slices.Equal(c.Audience, jwt.Audience{"api"}) {
				t.Errorf("Audience = %#v, want a one-element list either way", c.Audience)
			}
		})
	}
}
