package jwt

// Verifier checks the signature of a token. An implementation is bound to one
// algorithm; [Parse] compares the token's alg header against it and rejects a
// mismatch, which is what prevents algorithm confusion.
//
// Implementations must be safe for concurrent use.
type Verifier interface {
	// Algorithm reports the algorithm this verifier accepts.
	Algorithm() string

	// Verify reports whether signature is a valid signature over signingInput,
	// returning [ErrSignatureInvalid] when it is not.
	Verify(signingInput []byte, signature []byte) error
}
