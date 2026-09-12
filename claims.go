package jwt

import "time"

// The registered claim names this package looks at by itself. They appear in
// errors, so that "which claim is missing" is answerable without parsing text.
const (
	claimExpiration = "exp"
	claimNotBefore  = "nbf"
)

// RegisteredClaims holds the seven claims RFC 7519 registers, with the JSON
// tags they need and setters that take a [time.Time].
//
// Embedding it is a convenience, not a requirement: [Sign] and [Parse] accept
// anything [encoding/json] handles, a map included. Embed it by value when you
// want the standard fields alongside your own.
//
//	type Claims struct {
//		jwt.RegisteredClaims
//		UserID string `json:"user_id"`
//	}
//
// Do not give the outer struct a field with a JSON name this type already uses.
// The shallower one wins and the embedded one is never written, so the claim
// would go out under your field and be looked for under this one.
type RegisteredClaims struct {
	// ID is the jti claim: an identifier unique among the tokens an issuer
	// produces. This package neither generates nor checks it. It exists so that
	// an application can keep a revocation list or refuse a replayed token,
	// which needs storage this package does not have.
	ID string `json:"jti,omitempty"`

	// Audience is the aud claim: who the token is meant for. A token may name
	// several recipients, which is why this is a list even when it holds one
	// name. See [Audience] for how the two wire forms are read.
	//
	// Validated by [ParseOptions.ExpectedAudience].
	Audience Audience `json:"aud,omitempty"`

	// Issuer is the iss claim: who produced the token. Compared byte for byte,
	// with no normalization, so it must match exactly.
	//
	// Validated by [ParseOptions.ExpectedIssuer].
	Issuer string `json:"iss,omitempty"`

	// Subject is the sub claim: who the token is about, usually a user
	// identifier. This package never validates it; only the application knows
	// what a subject means.
	Subject string `json:"sub,omitempty"`
	// Expiration is the exp claim: seconds since the Unix epoch, after which the
	// token must be rejected. The moment itself is already expired.
	Expiration int64 `json:"exp,omitempty"`
	// NotBefore is the nbf claim: seconds since the Unix epoch, before which the
	// token must be rejected. The moment itself is valid.
	NotBefore int64 `json:"nbf,omitempty"`
	// IssuedAt is the iat claim: seconds since the Unix epoch at which the token
	// was produced. It never makes a token invalid on its own, so nothing here
	// checks it. Set it with [RegisteredClaims.SetIssuedAt] when you want to
	// know a token's age, or to refuse every token issued before some moment.
	IssuedAt int64 `json:"iat,omitempty"`
}

func (c *RegisteredClaims) SetID(id string) {
	c.ID = id
}

func (c *RegisteredClaims) SetAudience(aud Audience) {
	c.Audience = aud
}

func (c *RegisteredClaims) SetIssuer(iss string) {
	c.Issuer = iss
}

func (c *RegisteredClaims) SetSubject(sub string) {
	c.Subject = sub
}

func (c *RegisteredClaims) SetExpiration(exp time.Time) {
	c.Expiration = exp.Unix()
}

func (c *RegisteredClaims) SetNotBefore(nbf time.Time) {
	c.NotBefore = nbf.Unix()
}

func (c *RegisteredClaims) SetIssuedAt(iat time.Time) {
	c.IssuedAt = iat.Unix()
}
