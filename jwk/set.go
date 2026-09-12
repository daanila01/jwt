package jwk

import (
	"encoding/json"
	"fmt"
)

// Set is a JWK Set: the document a provider publishes at its well-known
// address, holding every key it currently signs with.
//
// There is usually more than one. Rotating a key means publishing the new one
// before retiring the old, so both are live while tokens signed by the old are
// still in flight, and the kid in a token's header is what tells them apart.
type Set struct {
	keys []*Key

	// skipped counts the entries that did not parse. A provider may publish key
	// types this package does not implement, and one of those must not make the
	// rest unreadable.
	skipped []error
}

type setJSON struct {
	Keys []json.RawMessage `json:"keys"`
}

// ParseSet reads a JWK Set.
//
// An entry that cannot be read is skipped rather than fatal, and the reason is
// kept in [Set.Skipped]. This is deliberate: providers add key types over time,
// and a verifier that refused the whole document the day an unfamiliar one
// appeared would stop working for reasons unrelated to any token it was given.
//
// A document where nothing at all could be read is an error, since that is not
// forward compatibility but a document this package cannot use.
func ParseSet(data []byte) (*Set, error) {
	var raw setJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyInvalid, err)
	}
	if raw.Keys == nil {
		return nil, fmt.Errorf("%w: no keys member", ErrKeyInvalid)
	}

	s := &Set{}
	for i, entry := range raw.Keys {
		k, err := Parse(entry)
		if err != nil {
			s.skipped = append(s.skipped, fmt.Errorf("key %d: %w", i, err))
			continue
		}
		s.keys = append(s.keys, k)
	}

	if len(s.keys) == 0 && len(s.skipped) > 0 {
		return nil, fmt.Errorf("%w: none of the %d keys could be read", ErrKeyInvalid, len(s.skipped))
	}

	return s, nil
}

// Keys returns every key that was read, in the order the document listed them.
func (s *Set) Keys() []*Key {
	return s.keys
}

// Skipped returns one error per entry that could not be read. Worth logging:
// silence here is how a provider's new key type goes unnoticed until the day
// the old one is retired.
func (s *Set) Skipped() []error {
	return s.skipped
}

// ByID returns the key a token's kid names.
//
// This is the lookup a verifier does, and the only one it should do. Choosing a
// key by the token's alg instead would let whoever sent the token choose how it
// is checked, which is the shape of the algorithm confusion attack: a token
// signed with RSA, re-labelled HS256, and verified with the public key as the
// HMAC secret.
func (s *Set) ByID(kid string) (*Key, bool) {
	for _, k := range s.keys {
		if k.ID == kid {
			return k, true
		}
	}

	return nil, false
}

// Only returns the single key in the set, for the common case of a provider
// that publishes one and tokens that carry no kid.
//
// It reports false when the set holds anything other than exactly one key,
// because picking arbitrarily from several would make verification depend on
// document order.
func (s *Set) Only() (*Key, bool) {
	if len(s.keys) != 1 {
		return nil, false
	}

	return s.keys[0], true
}
