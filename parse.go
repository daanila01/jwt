package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DefaultMaxTokenSize is the input limit [Parse] applies when
// [ParseOptions.MaxTokenSize] is zero. The limit is checked before anything is
// decoded, because decoding allocates in proportion to the input.
const DefaultMaxTokenSize = 1024 * 30

// ParseOptions configures a call to [Parse]. The zero value is valid: the
// signature is still verified, and no claims are validated.
type ParseOptions struct {
	// MaxTokenSize is the largest input accepted, in bytes. Zero means
	// [DefaultMaxTokenSize].
	MaxTokenSize int

	// NotBeforeValidation checks the nbf claim. A token without one is rejected.
	NotBeforeValidation bool

	// ExpirationValidation checks the exp claim. A token without one is rejected,
	// so a token that never expires does not pass silently.
	ExpirationValidation bool

	// Time is the moment to validate against. Zero means the current time. Set it
	// in tests instead of sleeping.
	Time time.Time

	// ClockSkew is how far the clocks of the issuer and this machine are allowed
	// to disagree. Both windows widen by this much, so a token is accepted a
	// little before nbf and a little after exp. Typical values are tens of
	// seconds. A negative value narrows the windows instead.
	ClockSkew time.Duration
}

// Parse verifies a token and decodes it into h and c.
//
// The signature is always verified. Claim validation is opt-in through opts, and
// nothing in the claims is read before the signature checks out. A token whose
// alg header is "none", or does not match verifier, is rejected before any
// signature work is done.
//
// Pass nil for h or c to skip decoding that half; the token is still verified in
// full. Only a literal nil: a nil pointer stored in an interface is not nil and
// will panic.
//
// Decoding merges into h and c and does not clear them first, so a field set by
// an earlier token survives one that omits it. Pass freshly zeroed values.
func Parse(token string, h headers, c claims, verifier Verifier, opts ParseOptions) error {
	if h == nil {
		h = &RegisteredHeaders{}
	}
	if c == nil {
		c = &RegisteredClaims{}
	}
	if h.registeredHeaders() == nil {
		return fmt.Errorf("%w: headers is nil", ErrTokenInvalid)
	}
	if c.registeredClaims() == nil {
		return fmt.Errorf("%w: claims is nil", ErrTokenInvalid)
	}
	if verifier == nil {
		return fmt.Errorf("%w: verifier is nil", ErrArgumentInvalid)
	}
	if len(token) == 0 {
		return fmt.Errorf("%w: token is empty", ErrTokenInvalid)
	}

	prepareParseOptions(&opts)

	if len(token) > opts.MaxTokenSize {
		return fmt.Errorf("%w: token is too large, allowed %d bytes", ErrTokenInvalid, opts.MaxTokenSize)
	}

	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return fmt.Errorf("%w: expected 3 segments, got %d", ErrTokenInvalid, len(segments))
	}
	for i, segment := range segments {
		if len(segment) == 0 {
			return fmt.Errorf("%w: segment %d is empty", ErrTokenInvalid, i+1)
		}
	}

	if err := parseHeaders(segments[0], h, verifier); err != nil {
		return err
	}

	sDec, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return fmt.Errorf("%w: failed to decode signature: %w", ErrTokenInvalid, err)
	}
	if err := verifier.Verify([]byte(segments[0]+"."+segments[1]), sDec); err != nil {
		return err
	}

	if err := parseClaims(segments[1], c, opts); err != nil {
		return err
	}

	return nil
}

func prepareParseOptions(opts *ParseOptions) {
	if opts.MaxTokenSize == 0 {
		opts.MaxTokenSize = DefaultMaxTokenSize
	}
	if opts.Time.IsZero() {
		opts.Time = time.Now()
	}
}

func parseHeaders(segment string, h headers, verifier Verifier) error {
	hDec, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("%w: failed to decode headers: %w", ErrTokenInvalid, err)
	}
	if hDec[0] != '{' {
		return fmt.Errorf("%w: headers is not a JSON object", ErrTokenInvalid)
	}
	if err := json.Unmarshal(hDec, h); err != nil {
		return fmt.Errorf("%w: failed to unmarshal headers: %w", ErrTokenInvalid, err)
	}

	alg := h.registeredHeaders().Algorithm
	if alg == "" {
		return fmt.Errorf("%w: algorithm not found in header", ErrTokenInvalid)
	} else if alg == "none" {
		return fmt.Errorf("%w: algorithm is none", ErrTokenInvalid)
	} else if alg != verifier.Algorithm() {
		return fmt.Errorf("%w: algorithm mismatch: expected %s, got %s", ErrTokenInvalid, verifier.Algorithm(), alg)
	}

	return nil
}

func parseClaims(segment string, c claims, opts ParseOptions) error {
	cDec, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("%w: failed to decode claims: %w", ErrTokenInvalid, err)
	}
	if cDec[0] != '{' {
		return fmt.Errorf("%w: claims is not a JSON object", ErrTokenInvalid)
	}
	if err := json.Unmarshal(cDec, c); err != nil {
		return fmt.Errorf("%w: failed to unmarshal claims: %w", ErrTokenInvalid, err)
	}

	if opts.ExpirationValidation {
		exp := c.registeredClaims().Expiration
		if exp == 0 {
			return fmt.Errorf("%w: %w: expiration not found", ErrTokenInvalid, ErrClaimMissing)
		}
		if !opts.Time.Add(-opts.ClockSkew).Before(time.Unix(exp, 0)) {
			return ErrExpired
		}
	}

	if opts.NotBeforeValidation {
		nbf := c.registeredClaims().NotBefore
		if nbf == 0 {
			return fmt.Errorf("%w: %w: not before not found", ErrTokenInvalid, ErrClaimMissing)
		}
		if opts.Time.Add(opts.ClockSkew).Before(time.Unix(nbf, 0)) {
			return ErrNotYetValid
		}
	}

	return nil
}
