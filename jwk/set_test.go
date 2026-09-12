package jwk_test

import (
	"errors"
	"testing"

	"github.com/daanila01/jwt/jwk"
)

// A set the way a provider publishes one: several keys, told apart by kid.
const testSet = `{"keys":[
	{"kty":"EC","kid":"2024-06","crv":"P-256",
	 "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	 "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
	{"kty":"OKP","kid":"2024-07","crv":"Ed25519",
	 "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
]}`

func TestParseSet(t *testing.T) {
	s, err := jwk.ParseSet([]byte(testSet))
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}

	if got := len(s.Keys()); got != 2 {
		t.Fatalf("read %d keys, want 2", got)
	}
	if got := len(s.Skipped()); got != 0 {
		t.Errorf("skipped %d keys, want none: %v", got, s.Skipped())
	}

	k, ok := s.ByID("2024-07")
	if !ok {
		t.Fatal("ByID() did not find the key")
	}
	v, err := k.Verifier()
	if err != nil {
		t.Fatalf("Verifier() error = %v", err)
	}
	if v.Algorithm() != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", v.Algorithm())
	}

	if _, ok := s.ByID("2023-01"); ok {
		t.Error("ByID() found a key that is not there")
	}
}

// TestSetSkipsWhatItCannotRead is the behaviour that keeps a verifier working
// on the day its provider publishes a key type this package does not know.
// Failing the whole document then would take the service down for a reason
// unrelated to any token it was handed.
func TestSetSkipsWhatItCannotRead(t *testing.T) {
	const mixed = `{"keys":[
		{"kty":"magic","kid":"future"},
		{"kty":"EC","kid":"2024-06","crv":"P-256",
		 "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		 "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
		{"kty":"EC","kid":"broken","crv":"P-256","x":"AA","y":"AA"}
	]}`

	s, err := jwk.ParseSet([]byte(mixed))
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}

	if got := len(s.Keys()); got != 1 {
		t.Errorf("read %d keys, want the one that was readable", got)
	}
	if got := len(s.Skipped()); got != 2 {
		t.Errorf("skipped %d, want 2", got)
	}
	if _, ok := s.ByID("2024-06"); !ok {
		t.Error("the readable key is missing from the set")
	}
}

func TestParseSetRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"not json", `{`},
		{"no keys member", `{"jwks":[]}`},
		{"nothing readable", `{"keys":[{"kty":"magic"},{"kty":"also-magic"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := jwk.ParseSet([]byte(tt.doc)); !errors.Is(err, jwk.ErrKeyInvalid) {
				t.Fatalf("ParseSet() error = %v, want %v", err, jwk.ErrKeyInvalid)
			}
		})
	}

	t.Run("an empty set is not an error", func(t *testing.T) {
		s, err := jwk.ParseSet([]byte(`{"keys":[]}`))
		if err != nil {
			t.Fatalf("ParseSet() error = %v", err)
		}
		if len(s.Keys()) != 0 {
			t.Error("an empty document produced keys")
		}
	})
}

// TestOnly covers the common small case: one key, and tokens that carry no kid.
func TestOnly(t *testing.T) {
	single := `{"keys":[{"kty":"OKP","crv":"Ed25519",
		"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`

	s, err := jwk.ParseSet([]byte(single))
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}
	if _, ok := s.Only(); !ok {
		t.Error("Only() found nothing in a set of one")
	}

	many, err := jwk.ParseSet([]byte(testSet))
	if err != nil {
		t.Fatalf("ParseSet() error = %v", err)
	}
	if _, ok := many.Only(); ok {
		t.Error("Only() picked from a set of two, which would make verification depend on order")
	}
}
