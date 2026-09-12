package jwt

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
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

	// ExpectedIssuer is the iss claim the token must carry, compared byte for
	// byte. An empty value skips the check.
	ExpectedIssuer string

	// ExpectedAudience is this verifier's own name, which must appear among the
	// token's aud claim. One name, because a verifier is one service, while a
	// token may be addressed to several. An empty value skips the check; a
	// non-empty one also rejects a token that carries no audience at all.
	ExpectedAudience string

	// NotBeforeValidation checks the nbf claim. A token without one is rejected.
	NotBeforeValidation bool

	// ExpirationValidation checks the exp claim. A token without one is rejected,
	// so a token that never expires does not pass silently.
	ExpirationValidation bool

	// Time is the moment to validate against. Zero means the current time. Set it
	// in tests instead of sleeping.
	Time time.Time

	// ResolveVerifier picks the verifier from the token's header, for a service
	// that holds more than one key. When it is set the verifier argument is
	// ignored and may be nil.
	//
	// Choose by kid and nothing else. The algorithm must come from your own
	// record of the key, never from the token's alg: letting the token pick how
	// it is checked is the whole of the algorithm confusion attack. The alg in
	// the header is still compared against whatever verifier is returned, so a
	// resolver that obeys this rule keeps that protection intact and one that
	// does not throws it away.
	//
	//	opts.ResolveVerifier = func(h map[string]any) (jwt.Verifier, error) {
	//		kid, _ := h["kid"].(string)
	//		key, ok := set.ByID(kid)
	//		if !ok {
	//			return nil, fmt.Errorf("unknown key %q", kid)
	//		}
	//		return key.Verifier()
	//	}
	ResolveVerifier func(header map[string]any) (Verifier, error)

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
// full either way.
//
// A header map is filled in place, so give one that has been made:
//
//	header := map[string]any{}
//	err := jwt.Parse(token, header, &claims, verifier, jwt.ParseOptions{})
//
// A nil map cannot be filled, which is why nil reads as "I do not need the
// header" rather than as a mistake. Claims follow the [encoding/json] rule
// instead: give a pointer, or there is nowhere to write.
//
// Decoding merges and does not clear first, so a field left by an earlier token
// survives one that omits it. Pass freshly zeroed values.
func Parse(token string, h map[string]any, c any, verifier Verifier, options ...ParseOptions) error {
	opts := ParseOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	prepareParseOptions(&opts)

	if verifier == nil && opts.ResolveVerifier == nil {
		return fmt.Errorf("%w: verifier is nil", ErrArgumentInvalid)
	}
	// A literal nil means "decode nothing"; a nil held inside an interface is a
	// caller's uninitialised variable, and writing into it is impossible.
	if c != nil && isNil(c) {
		return fmt.Errorf("%w: claims is nil", ErrArgumentInvalid)
	}
	if len(token) == 0 {
		return fmt.Errorf("%w: token is empty", ErrTokenInvalid)
	}

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

	// The header is read either way, because alg lives in it. A map given by the
	// caller is filled in place, since a map value carries a reference to the
	// same storage; nil means they did not ask for it, and a throwaway is used.
	header := h
	if header == nil {
		header = make(map[string]any)
	}
	if err := unmarshalBase64(segments[0], &header); err != nil {
		return fmt.Errorf("%w: failed to unmarshal header: %w", ErrTokenInvalid, err)
	}
	// The key is chosen before the algorithm is compared, and by kid rather
	// than by alg: the comparison below then still means something. Resolving by
	// what the token says about itself would be handing the attacker the choice.
	if opts.ResolveVerifier != nil {
		resolved, err := opts.ResolveVerifier(header)
		if err != nil {
			return fmt.Errorf("%w: resolving the verifier: %w", ErrTokenInvalid, err)
		}
		if resolved == nil {
			return fmt.Errorf("%w: the resolver returned no verifier", ErrArgumentInvalid)
		}
		verifier = resolved
	}

	if alg, ok := header[headerAlgorithm]; ok {
		if alg == "" {
			return fmt.Errorf("%w: algorithm is empty", ErrTokenInvalid)
		}
		if alg == "none" {
			return fmt.Errorf("%w: algorithm is none", ErrTokenInvalid)
		}
		if alg != verifier.Algorithm() {
			return fmt.Errorf("%w: algorithm mismatch: expected %s, got %s", ErrTokenInvalid, verifier.Algorithm(), alg)
		}
	} else {
		return fmt.Errorf("%w: algorithm not found in header", ErrTokenInvalid)
	}

	// RFC 7519 requires the claims set to be a JSON object. Unmarshalling the
	// literal null into a struct is a no-op rather than an error, so without
	// this a token carrying null would parse into empty claims and pass.
	cDec, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return fmt.Errorf("%w: failed to decode claims: %w", ErrTokenInvalid, err)
	}
	if len(bytes.TrimLeft(cDec, " \t\r\n")) == 0 || bytes.TrimLeft(cDec, " \t\r\n")[0] != '{' {
		return fmt.Errorf("%w: claims is not a JSON object", ErrTokenInvalid)
	}

	sDec, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil {
		return fmt.Errorf("%w: failed to decode signature: %w", ErrTokenInvalid, err)
	}
	if err := verifier.Verify([]byte(segments[0]+"."+segments[1]), sDec); err != nil {
		return err
	}

	if opts.ExpectedIssuer != "" || opts.ExpectedAudience != "" ||
		opts.NotBeforeValidation || opts.ExpirationValidation {
		var cl RegisteredClaims
		if err := unmarshalBase64(segments[1], &cl); err != nil {
			return fmt.Errorf("%w: failed to unmarshal claims: %w", classifyUnmarshal(err), err)
		}
		if opts.ExpectedIssuer != "" && cl.Issuer != opts.ExpectedIssuer {
			return fmt.Errorf("%w: issuer mismatch: expected %s, got %s", ErrTokenInvalid, opts.ExpectedIssuer, cl.Issuer)
		}
		if opts.ExpectedAudience != "" && !slices.Contains(cl.Audience, opts.ExpectedAudience) {
			return fmt.Errorf("%w: audience mismatch: expected %s, got %s", ErrTokenInvalid, opts.ExpectedAudience, cl.Audience)
		}
		if opts.NotBeforeValidation {
			if cl.NotBefore == 0 {
				return fmt.Errorf("%w: %s", ErrClaimMissing, claimNotBefore)
			}
			// The moment nbf names is already valid, so only a later one fails.
			if cl.NotBefore > opts.Time.Add(opts.ClockSkew).Unix() {
				return ErrNotYetValid
			}
		}
		if opts.ExpirationValidation {
			if cl.Expiration == 0 {
				return fmt.Errorf("%w: %s", ErrClaimMissing, claimExpiration)
			}
			// The moment exp names is already expired, which is why this is not
			// symmetric with the check above.
			if cl.Expiration <= opts.Time.Add(-opts.ClockSkew).Unix() {
				return ErrExpired
			}
		}
	}

	if c != nil {
		if err := unmarshalBase64(segments[1], c); err != nil {
			return fmt.Errorf("%w: failed to unmarshal claims: %w", classifyUnmarshal(err), err)
		}
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
