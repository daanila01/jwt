package jwt

import (
	"encoding/base64"
	"encoding/json"
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

// checkDestination reports whether a value can receive a JSON object at all.
//
// A failed decode has two very different causes, and they want different
// answers from an HTTP handler: a destination of the wrong shape is the
// caller's mistake and says nothing about the token, while a field of the wrong
// type inside the payload is the token's.
//
// Telling them apart from the error afterwards looked possible and was not:
// json.UnmarshalTypeError names the field it failed on, but not when the
// failure came out of a type's own UnmarshalJSON, and whether it does has
// changed between Go releases. So the destination is judged before json runs,
// where the answer depends on nothing but the type in hand.
//
// A claims set is a JSON object, so only a pointer to a struct, a map or an
// interface can hold one. A *string or a *[]string cannot, whatever the token
// says.
func checkDestination(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("%w: claims must be a non-nil pointer", ErrArgumentInvalid)
	}

	switch rv.Elem().Kind() {
	case reflect.Struct, reflect.Map, reflect.Interface:
		return nil
	}

	return fmt.Errorf("%w: a JSON object cannot be read into %T", ErrArgumentInvalid, v)
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
