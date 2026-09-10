package jwt

import "errors"

// Errors reported by this package. They are returned wrapped, so match them with
// [errors.Is] rather than by comparison. A caller usually needs to tell three
// cases apart: a token that is malformed ([ErrTokenInvalid]), one that is
// well-formed but not authentic ([ErrSignatureInvalid]), and one that is
// authentic but no longer valid ([ErrExpired], [ErrNotYetValid]).
var (
	ErrClaimMissing     = errors.New("jwt: claim missing")
	ErrExpired          = errors.New("jwt: expired")
	ErrNotYetValid      = errors.New("jwt: not yet valid")
	ErrSignatureInvalid = errors.New("jwt: signature invalid")
	ErrTokenInvalid     = errors.New("jwt: token invalid")
	ErrKeyInvalid       = errors.New("jwt: key invalid")
	ErrArgumentInvalid  = errors.New("jwt: argument invalid")
)
