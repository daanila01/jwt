package jwt

import "encoding/json"

// Audience is the aud claim, always held as a list.
//
// RFC 7519 allows two forms on the wire: a single string when there is one
// recipient, and an array otherwise. Both are read into a list here, so an
// application never has to ask which form arrived. Tokens are always written
// as an array, which every implementation accepts.
type Audience []string

// UnmarshalJSON reads either wire form: a JSON array of strings, or a single
// string, which becomes a list of one.
func (a *Audience) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*a = nil
		return nil
	}

	if len(data) > 0 && data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*a = arr
		return nil
	}

	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*a = []string{str}

	return nil
}
