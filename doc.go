// Package jwt signs and verifies JSON Web Tokens.
//
// The package implements JWS, the signed form of a JWT described by RFC 7515,
// with claims as defined by RFC 7519. JWE, the encrypted form, is out of scope.
// It has no dependencies outside the standard library.
//
// # Claims are your own type
//
// Claims are not held in a map. Declare a struct, embed [RegisteredClaims] into
// it by value, and pass it by pointer:
//
//	type Claims struct {
//		jwt.RegisteredClaims
//		UserID string `json:"user_id"`
//	}
//
// Embedding is what makes the type usable here: it promotes an unexported method
// that this package calls to read and write the registered claims. A type that
// does not embed [RegisteredClaims] cannot be passed to [Sign] or [Parse].
//
// The consequence is that a claim which is not a field does not exist. Nothing
// can be added at run time, and a claim present in a token but absent from your
// struct is dropped when the token is parsed.
//
// # Verification
//
// [Parse] always verifies the signature. Claim validation is opt-in through
// [ParseOptions].
//
// The algorithm is never taken from the token. You supply a [Verifier] that is
// bound to one algorithm, and the token's alg header is only compared against it.
// A token declaring "none", or an algorithm other than the verifier's, is
// rejected. This is what prevents algorithm confusion, where a token signed with
// RSA is re-signed with HMAC using the public key as the secret.
//
// # Concurrency
//
// Implementations of [Signer] and [Verifier] are safe for concurrent use: create
// one at startup and share it. The claims and header values passed to [Sign] and
// [Parse] are not, and are expected to belong to a single call.
package jwt
