package jwt

// claims is satisfied by any type that embeds [RegisteredClaims]. The method is
// unexported, so no type outside this package can implement it another way.
type claims interface {
	registeredClaims() *RegisteredClaims
}

// RegisteredClaims holds the claims registered by RFC 7519 that this package
// understands. Embed it by value in your own claims type and pass that type by
// pointer; the methods have pointer receivers, and a value would be written to a
// copy that is then discarded.
//
// Do not declare a field in the outer struct with a JSON name this type already
// uses. The shallower field wins silently, this package keeps reading the
// embedded zero value, and validation stops working without reporting anything.
type RegisteredClaims struct {
	// Expiration is the exp claim: seconds since the Unix epoch, after which the
	// token must be rejected. The moment itself is already expired.
	Expiration int64 `json:"exp,omitempty"`
	// NotBefore is the nbf claim: seconds since the Unix epoch, before which the
	// token must be rejected. The moment itself is valid.
	NotBefore int64 `json:"nbf,omitempty"`
}

func (c *RegisteredClaims) registeredClaims() *RegisteredClaims {
	return c
}
