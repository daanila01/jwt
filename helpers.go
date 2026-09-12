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
