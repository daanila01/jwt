package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

func isNil(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		if rv.IsNil() {
			return true
		}
	}

	return false
}

// classifyUnmarshal decides whose fault a failed decode was.
//
// encoding/json reports two very different things through the same call. A
// destination that cannot be written to, or a whole value that does not fit the
// type it was given, is the caller's mistake: the token may be perfectly good.
// A field inside the payload with the wrong type, or JSON that does not parse,
// is the token's.
//
// The two answer differently at the HTTP layer, so they must not share a
// sentinel.
func classifyUnmarshal(err error) error {
	var invalid *json.InvalidUnmarshalError
	if errors.As(err, &invalid) {
		return ErrArgumentInvalid
	}

	// A type error names the field it failed on. An empty name means the
	// mismatch was at the top level, which is a destination of the wrong shape.
	var mismatch *json.UnmarshalTypeError
	if errors.As(err, &mismatch) && mismatch.Field == "" {
		return ErrArgumentInvalid
	}

	return ErrTokenInvalid
}

func marshalBase64(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal json: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func unmarshalBase64(data string, v any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("failed to decode base64: %w", err)
	}
	if err := json.Unmarshal(decoded, v); err != nil {
		return fmt.Errorf("failed to unmarshal json: %w", err)
	}
	return nil
}
