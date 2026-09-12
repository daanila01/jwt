// Package jwt signs and verifies JSON Web Tokens.
//
// The package implements JWS, the signed form of a JWT described by RFC 7515,
// with claims as defined by RFC 7519. JWE, the encrypted form, is out of scope.
// It has no dependencies outside the standard library.
//
// # Claims are yours, the header is mostly ours
//
// Claims are whatever [encoding/json] accepts. Usually that is a struct of your
// own; a map does just as well when the names are only known at run time.
//
//	type Claims struct {
//		jwt.RegisteredClaims
//		UserID string `json:"user_id"`
//	}
//
// Embedding [RegisteredClaims] is optional. It carries the seven names RFC 7519
// registers, with the JSON tags they need and setters that take a [time.Time],
// which is where seconds tend to be confused with something else. Nothing here
// requires it: a bare map reaches the same token.
//
// [Sign] writes nothing into your claims. A token expires only if you put an
// exp in it.
//
// The header is a map, because it holds three or four flat string keys and
// little else. Pass nil when you have nothing to add. The one key that is not
// yours is alg: it is written from the signer over whatever you left there, so
// a token cannot claim an algorithm other than the one that signed it.
// Everything else, typ included, passes through untouched.
//
// # Verification
//
// [Parse] always verifies the signature. Claim validation is opt-in through
// [ParseOptions], and nothing in the claims is read until the signature checks
// out.
//
// The algorithm is never taken from the token. You supply a [Verifier] bound to
// one algorithm, and the token's alg header is only compared against it. A token
// declaring "none", or any algorithm other than the verifier's, is rejected
// before a signature is computed. This is what prevents algorithm confusion,
// where a token signed with RSA is re-signed with HMAC using the public key as
// the secret.
//
// The two destinations are not shaped alike, because the data is not. A header
// map is filled in place, so hand over one that has been made; a nil map cannot
// be, which is why nil reads as "I do not need the header". Claims follow the
// [encoding/json] rule instead: pass a pointer, or there is nowhere to write.
//
// Pass nil for either to skip decoding that half while still verifying the
// token in full. Decoding merges rather than clears, so a field left by an
// earlier token survives one that omits it.
//
// # Concurrency
//
// Implementations of [Signer] and [Verifier] are safe for concurrent use: build
// one at startup and share it. The header and claims passed to [Sign] and
// [Parse] are not, and are expected to belong to a single call.
package jwt
