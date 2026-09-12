package jwt_test

import (
	"errors"
	"testing"

	"github.com/daanila01/jwt"
)

// The branches covered here are the ones the package itself can never trigger:
// they exist because Signer is a public interface and because a caller's claims
// type may carry its own MarshalJSON. Nothing in this package fails there, but
// somebody else's code can, and the error has to travel rather than be lost.

var errStub = errors.New("stub failure")

// failingSigner is what a signer backed by a key store looks like when the key
// store is down.
type failingSigner struct{}

func (failingSigner) Algorithm() string               { return jwt.AlgorithmHS256 }
func (failingSigner) Sign([]byte) ([]byte, error)     { return nil, errStub }
func (failingSigner) Verify(_ []byte, _ []byte) error { return errStub }

type failingClaims struct {
	jwt.RegisteredClaims
}

func (failingClaims) MarshalJSON() ([]byte, error) { return nil, errStub }

// failingValue is something a caller might put in the header map: the package
// cannot know it will refuse to marshal, and the error has to travel.
type failingValue struct{}

func (failingValue) MarshalJSON() ([]byte, error) { return nil, errStub }

func TestSignPropagatesSignerFailure(t *testing.T) {
	_, err := jwt.Sign(nil, &jwt.RegisteredClaims{}, failingSigner{})
	if !errors.Is(err, errStub) {
		t.Fatalf("Sign() error = %v, want it to wrap the signer's own error", err)
	}
}

func TestSignPropagatesClaimsMarshalFailure(t *testing.T) {
	_, err := jwt.Sign(nil, &failingClaims{}, testSigner(t))
	if !errors.Is(err, errStub) {
		t.Fatalf("Sign() error = %v, want it to wrap the marshaller's own error", err)
	}
}

func TestSignPropagatesHeaderMarshalFailure(t *testing.T) {
	h := map[string]any{"kid": failingValue{}}
	_, err := jwt.Sign(h, &jwt.RegisteredClaims{}, testSigner(t))
	if !errors.Is(err, errStub) {
		t.Fatalf("Sign() error = %v, want it to wrap the marshaller's own error", err)
	}
}

// TestVerifierAlgorithmIsWhatIsCompared closes the loop on algorithm confusion
// from the other side: a verifier that claims a different algorithm must refuse
// a token this package signed, even though the signature itself would check out.
func TestVerifierAlgorithmIsWhatIsCompared(t *testing.T) {
	token, err := jwt.Sign(nil, &jwt.RegisteredClaims{Subject: "u1"}, testSigner(t))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if err := jwt.Parse(token, nil, nil, mislabelled{testSigner(t)}, jwt.ParseOptions{}); !errors.Is(err, jwt.ErrTokenInvalid) {
		t.Fatalf("Parse() error = %v, want the algorithm mismatch to be caught", err)
	}
}

// mislabelled verifies correctly but names a different algorithm.
type mislabelled struct{ *jwt.HMAC }

func (mislabelled) Algorithm() string { return "RS256" }
