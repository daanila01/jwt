package jwt

// Signer produces the signature of a token. An implementation carries both the
// algorithm and the key, so the two cannot be mismatched, and validates the key
// once when it is constructed rather than on every call.
//
// Implementations must be safe for concurrent use.
type Signer interface {
	// Algorithm reports the value written to the alg header parameter.
	Algorithm() string

	// Sign returns the signature over signingInput, which is the encoded header
	// and claims joined by a period.
	Sign(signingInput []byte) ([]byte, error)
}
