package jwt_test

import (
	"encoding/json"
	"strings"
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

func benchSigner(b *testing.B) *jwt.HS256 {
	b.Helper()

	s, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		b.Fatalf("NewHS256() error = %v", err)
	}

	return s
}

func BenchmarkSign(b *testing.B) {
	s := benchSigner(b)
	exp := time.Now().Add(time.Hour)

	for _, tt := range benchPayloads() {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// a fresh value each time: Sign writes into it, and reusing one
				// would measure a second call that has less left to do
				c := tt.claims
				benchToken, benchErr = jwt.Sign(nil, &c, s, jwt.SignOptions{Expiration: exp})
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	s := benchSigner(b)
	exp := time.Now().Add(time.Hour)

	for _, tt := range benchPayloads() {
		b.Run(tt.name, func(b *testing.B) {
			c := tt.claims
			token, err := jwt.Sign(nil, &c, s, jwt.SignOptions{Expiration: exp})
			if err != nil {
				b.Fatalf("Sign() error = %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var out benchClaims
				benchErr = jwt.Parse(token, nil, &out, s, jwt.ParseOptions{})
			}
		})
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
	benchSigner256 *jwt.HS256
)

func BenchmarkHS256SignOnly(b *testing.B) {
	s := benchSigner(b)
	input := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchSignature, benchErr = s.Sign(input)
	}
}

func BenchmarkHS256VerifyOnly(b *testing.B) {
	s := benchSigner(b)
	input := []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9")

	sig, err := s.Sign(input)
	if err != nil {
		b.Fatalf("Sign() error = %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		benchErr = s.Verify(input, sig)
	}
}

// BenchmarkNewHS256 covers the one-off cost of building a signer, which a
// service pays at startup rather than per request. Worth a line so that nobody
// is tempted to build one per call.
func BenchmarkNewHS256(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// kept in a package-level variable: discarding it lets escape analysis
		// delete the allocation and the benchmark reports a fiction
		benchSigner256, benchErr = jwt.NewHS256(key)
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
