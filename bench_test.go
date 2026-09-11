package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// Benchmarks are table-driven the same way tests are: b.Run makes a sub-benchmark
// with its own name and its own b.N, so one function covers several shapes and
// each line of output can be compared with the others.
//
// Three rules the numbers depend on:
//
//   - the result goes into a package-level variable, or the compiler is free to
//     notice nobody wants it and delete the work;
//   - setup happens before b.ResetTimer, so building a key is not measured;
//   - nothing prints inside the loop.

var (
	benchToken string
	benchErr   error
)

type benchClaims struct {
	jwt.RegisteredClaims
	UserID string   `json:"user_id,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Scope  string   `json:"scope,omitempty"`
}

// payloads of three sizes, to show where JSON starts to outweigh the signature
func benchPayloads() []struct {
	name   string
	claims benchClaims
} {
	many := make([]string, 40)
	for i := range many {
		many[i] = "permission:resource:action:" + strings.Repeat("x", 16)
	}

	return []struct {
		name   string
		claims benchClaims
	}{
		{"small", benchClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "u1"},
		}},
		{"typical", benchClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       "01J8Z5R2QK9V3T6M",
				Subject:  "6f1c8a52-4e7b-4a2f-9f7e-2b0d6a1c9e84",
				Issuer:   "auth.example.com",
				Audience: jwt.Audience{"api.example.com"},
			},
			UserID: "6f1c8a52-4e7b-4a2f-9f7e-2b0d6a1c9e84",
			Roles:  []string{"user", "billing:read"},
		}},
		{"large", benchClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "u1"},
			Roles:            many,
			Scope:            strings.Repeat("openid profile email ", 20),
		}},
	}
}

func benchSigner(b *testing.B) *jwt.HMAC {
	b.Helper()

	s, err := jwt.NewHS256(benchKey[:32])
	if err != nil {
		b.Fatalf("NewHS256() error = %v", err)
	}

	return s
}

var benchKey = []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

// benchAlgorithm pairs a signer with the verifier that answers it. They are the
// same object for HMAC, whose key is symmetric, and different objects for the
// asymmetric families.
type benchAlgorithm struct {
	name     string
	signer   jwt.Signer
	verifier jwt.Verifier
}

// benchAlgorithms is the one place the list lives. Every benchmark below loops
// over it, so a new algorithm joins the whole report by adding a line.
func benchAlgorithms(b *testing.B) []benchAlgorithm {
	b.Helper()

	out := []benchAlgorithm{}

	for _, a := range []struct {
		name string
		new  func([]byte) (*jwt.HMAC, error)
		size int
	}{
		{"HS256", jwt.NewHS256, 32},
		{"HS384", jwt.NewHS384, 48},
		{"HS512", jwt.NewHS512, 64},
	} {
		s, err := a.new(benchKey[:a.size])
		if err != nil {
			b.Fatalf("%s: constructor error = %v", a.name, err)
		}
		out = append(out, benchAlgorithm{a.name, s, s})
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey() error = %v", err)
	}
	edSigner, err := jwt.NewEdDSASigner(priv)
	if err != nil {
		b.Fatalf("NewEdDSASigner() error = %v", err)
	}
	edVerifier, err := jwt.NewEdDSAVerifier(pub)
	if err != nil {
		b.Fatalf("NewEdDSAVerifier() error = %v", err)
	}
	out = append(out, benchAlgorithm{"EdDSA", edSigner, edVerifier})

	for _, c := range []struct {
		name  string
		curve elliptic.Curve
		newS  func(*ecdsa.PrivateKey) (*jwt.ECDSASigner, error)
		newV  func(*ecdsa.PublicKey) (*jwt.ECDSAVerifier, error)
	}{
		{"ES256", elliptic.P256(), jwt.NewES256Signer, jwt.NewES256Verifier},
		{"ES384", elliptic.P384(), jwt.NewES384Signer, jwt.NewES384Verifier},
		{"ES512", elliptic.P521(), jwt.NewES512Signer, jwt.NewES512Verifier},
	} {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			b.Fatalf("%s: GenerateKey() error = %v", c.name, err)
		}
		signer, err := c.newS(key)
		if err != nil {
			b.Fatalf("%s: signer: %v", c.name, err)
		}
		verifier, err := c.newV(&key.PublicKey)
		if err != nil {
			b.Fatalf("%s: verifier: %v", c.name, err)
		}
		out = append(out, benchAlgorithm{c.name, signer, verifier})
	}

	// One RSA key for all six: generating them is slow and the padding scheme
	// is what differs, not the key.
	rsaKey := benchRSAKey(b)
	for _, r := range []struct {
		name string
		newS func(*rsa.PrivateKey) (*jwt.RSASigner, error)
		newV func(*rsa.PublicKey) (*jwt.RSAVerifier, error)
	}{
		{"RS256", jwt.NewRS256Signer, jwt.NewRS256Verifier},
		{"RS384", jwt.NewRS384Signer, jwt.NewRS384Verifier},
		{"RS512", jwt.NewRS512Signer, jwt.NewRS512Verifier},
		{"PS256", jwt.NewPS256Signer, jwt.NewPS256Verifier},
		{"PS384", jwt.NewPS384Signer, jwt.NewPS384Verifier},
		{"PS512", jwt.NewPS512Signer, jwt.NewPS512Verifier},
	} {
		signer, err := r.newS(rsaKey)
		if err != nil {
			b.Fatalf("%s: signer: %v", r.name, err)
		}
		verifier, err := r.newV(&rsaKey.PublicKey)
		if err != nil {
			b.Fatalf("%s: verifier: %v", r.name, err)
		}
		out = append(out, benchAlgorithm{r.name, signer, verifier})
	}

	return out
}

var (
	benchRSAOnce sync.Once
	benchRSA     *rsa.PrivateKey
)

func benchRSAKey(b *testing.B) *rsa.PrivateKey {
	b.Helper()

	var err error
	benchRSAOnce.Do(func() {
		benchRSA, err = rsa.GenerateKey(rand.Reader, jwt.MinRSAKeyBits)
	})
	if err != nil {
		b.Fatalf("GenerateKey() error = %v", err)
	}

	return benchRSA
}

func BenchmarkSign(b *testing.B) {
	exp := time.Now().Add(time.Hour)

	for _, a := range benchAlgorithms(b) {
		for _, tt := range benchPayloads() {
			b.Run(a.name+"/"+tt.name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					// a fresh value each time: Sign writes into it, and reusing
					// one would measure a second call with less left to do
					c := tt.claims
					benchToken, benchErr = jwt.Sign(nil, &c, a.signer, jwt.SignOptions{Expiration: exp})
				}
			})
		}
	}
}

func BenchmarkParse(b *testing.B) {
	exp := time.Now().Add(time.Hour)

	for _, a := range benchAlgorithms(b) {
		for _, tt := range benchPayloads() {
			b.Run(a.name+"/"+tt.name, func(b *testing.B) {
				c := tt.claims
				token, err := jwt.Sign(nil, &c, a.signer, jwt.SignOptions{Expiration: exp})
				if err != nil {
					b.Fatalf("Sign() error = %v", err)
				}

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					var out benchClaims
					benchErr = jwt.Parse(token, nil, &out, a.verifier, jwt.ParseOptions{})
				}
			})
		}
	}
}

// BenchmarkParseValidation asks what the claim checks cost on top of the
// signature. The answer should be nothing worth seeing; if it is not, that is
// worth knowing.
func BenchmarkParseValidation(b *testing.B) {
	s := benchSigner(b)

	c := jwt.RegisteredClaims{Subject: "u1", Issuer: "auth", Audience: jwt.Audience{"api"}}
	token, err := jwt.Sign(nil, &c, s, jwt.SignOptions{
		Expiration: time.Now().Add(time.Hour),
		NotBefore:  time.Now().Add(-time.Hour),
	})
	if err != nil {
		b.Fatalf("Sign() error = %v", err)
	}

	cases := []struct {
		name string
		opts jwt.ParseOptions
	}{
		{"signature only", jwt.ParseOptions{}},
		{"every check on", jwt.ParseOptions{
			ExpirationValidation: true,
			NotBeforeValidation:  true,
			ExpectedIssuer:       "auth",
			ExpectedAudience:     "api",
			ClockSkew:            30 * time.Second,
		}},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var out jwt.RegisteredClaims
				benchErr = jwt.Parse(token, nil, &out, s, tt.opts)
			}
		})
	}
}

// The parallel pair answers a different question: whether sharing one signer
// across goroutines costs anything. If the per-operation figure does not improve
// with more cores, something is contended.
func BenchmarkSignParallel(b *testing.B) {
	s := benchSigner(b)
	exp := time.Now().Add(time.Hour)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c := jwt.RegisteredClaims{Subject: "u1"}
			benchToken, benchErr = jwt.Sign(nil, &c, s, jwt.SignOptions{Expiration: exp})
		}
	})
}

func BenchmarkParseParallel(b *testing.B) {
	s := benchSigner(b)

	c := jwt.RegisteredClaims{Subject: "u1"}
	token, err := jwt.Sign(nil, &c, s, jwt.SignOptions{Expiration: time.Now().Add(time.Hour)})
	if err != nil {
		b.Fatalf("Sign() error = %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var out jwt.RegisteredClaims
			benchErr = jwt.Parse(token, nil, &out, s, jwt.ParseOptions{})
		}
	})
}

// The two below measure the cryptography on its own, with none of the framing
// around it. Subtracting them from BenchmarkSign and BenchmarkParse says how
// much of a token's cost is JSON and base64 rather than HMAC, which is the
// number that decides whether optimising the encoding is worth anything.
var (
	benchSignature []byte
	benchSigner256 *jwt.HMAC
)

func BenchmarkSignOnly(b *testing.B) {
	input := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9")

	for _, a := range benchAlgorithms(b) {
		b.Run(a.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				benchSignature, benchErr = a.signer.Sign(input)
			}
		})
	}
}

func BenchmarkVerifyOnly(b *testing.B) {
	input := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9")

	for _, a := range benchAlgorithms(b) {
		b.Run(a.name, func(b *testing.B) {
			sig, err := a.signer.Sign(input)
			if err != nil {
				b.Fatalf("Sign() error = %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				benchErr = a.verifier.Verify(input, sig)
			}
		})
	}
}

// BenchmarkNewSigner covers the one-off cost of building a signer, which a
// service pays at startup rather than per request. Worth a line so that nobody
// is tempted to build one per call.
//
// EdDSA is left out: its constructor only checks a length, like these, and the
// key generation that would dominate the number belongs to the caller.
func BenchmarkNewSigner(b *testing.B) {
	for _, a := range []struct {
		name string
		new  func([]byte) (*jwt.HMAC, error)
		size int
	}{
		{"HS256", jwt.NewHS256, 32},
		{"HS384", jwt.NewHS384, 48},
		{"HS512", jwt.NewHS512, 64},
	} {
		b.Run(a.name, func(b *testing.B) {
			key := benchKey[:a.size]

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// kept in a package-level variable: discarding it lets escape
				// analysis delete the allocation and the benchmark reports a
				// fiction
				benchSigner256, benchErr = a.new(key)
			}
		})
	}
}

// BenchmarkAudienceUnmarshal covers the one claim with a hand-written decoder,
// in both wire forms, so a change to it cannot quietly become expensive.
func BenchmarkAudienceUnmarshal(b *testing.B) {
	cases := []struct {
		name string
		json []byte
	}{
		{"bare string", []byte(`"api.example.com"`)},
		{"array of one", []byte(`["api.example.com"]`)},
		{"array of several", []byte(`["api.example.com","web.example.com","admin.example.com"]`)},
	}

	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var a jwt.Audience
				benchErr = json.Unmarshal(tt.json, &a)
			}
		})
	}
}
