package jwt

const (
	headerTypeJWT = "JWT"
)

// headers is satisfied by any type that embeds [RegisteredHeaders]. The method
// is unexported, so no type outside this package can implement it another way.
type headers interface {
	registeredHeaders() *RegisteredHeaders
}

// RegisteredHeaders holds the JOSE header parameters this package understands.
// Embed it by value in your own header type and pass that type by pointer.
//
// Both fields are written by [Sign] from the signer, so setting them yourself has
// no effect. The type exists so that a caller can read them back after [Parse].
type RegisteredHeaders struct {
	// Type is the typ header parameter, always "JWT" for tokens this package signs.
	Type string `json:"typ,omitempty"`
	// Algorithm is the alg header parameter. On parse it is compared against the
	// verifier's algorithm and never used to choose one.
	Algorithm string `json:"alg,omitempty"`
}

func (h *RegisteredHeaders) registeredHeaders() *RegisteredHeaders {
	return h
}
