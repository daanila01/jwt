package jwt

import "testing"

// isNil is unexported, so this file is in package jwt rather than jwt_test.
// Everything else lives outside the package on purpose; this is the exception.

type embedByValue struct {
	RegisteredClaims
	UserID string
}

type embedByPointer struct {
	*RegisteredClaims
	UserID string
}

// TestIsNil covers every shape that can reach the helper, including the ones
// that make reflect panic. The two interfaces this package takes are satisfied
// only by pointers, so a value cannot arrive through them today, but a helper
// that dies on an ordinary input is a trap for whoever reuses it next.
func TestIsNil(t *testing.T) {
	var nilRegistered *RegisteredClaims
	var nilOuterValue *embedByValue
	var nilOuterPointer *embedByPointer

	tests := []struct {
		name string
		give any
		want bool
	}{
		{"untyped nil", nil, true},
		{"nil pointer to the registered set", nilRegistered, true},
		{"nil pointer to a type embedding it by value", nilOuterValue, true},
		{"nil pointer to a type embedding it by pointer", nilOuterPointer, true},
		{"live pointer", &RegisteredClaims{}, false},
		{"live pointer to an embedding type", &embedByValue{}, false},
		{"outer is live, embedded pointer is not", &embedByPointer{}, false},
		{"a struct value", RegisteredClaims{}, false},
		{"a string", "text", false},
		{"a number", 42, false},
		{"a nil map", map[string]string(nil), true},
		{"a nil slice", []string(nil), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("isNil() panicked on %T: %v", tt.give, r)
				}
			}()

			if got := isNil(tt.give); got != tt.want {
				t.Errorf("isNil(%#v) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}
