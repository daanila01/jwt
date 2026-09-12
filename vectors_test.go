package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/daanila01/jwt"
)

// The worked example from RFC 7515, Appendix A.1: a token, and the key that
// signed it, published by the authors of the specification.
//
// This is the only kind of test that proves interoperability. A round trip
// proves the package agrees with itself, which it would even if the base64
// alphabet were wrong in both directions.
const (
	rfc7515A1Key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

	rfc7515A1Token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

func rfc7515A1Verifier(t *testing.T) *jwt.HMAC {
	t.Helper()

	key, err := base64.RawURLEncoding.DecodeString(rfc7515A1Key)
	if err != nil {
		t.Fatalf("decoding the reference key: %v", err)
	}

	v, err := jwt.NewHS256(key)
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	return v
}

// TestRFC7515A1 verifies the reference token and reads its claims.
//
// The token cannot be reproduced byte for byte: its header carries a literal
// CRLF and a space inside the JSON, and Sign builds its own compact header.
// Verification is the half that matters, and it is the half a library gets
// wrong when its encoding is subtly off.
func TestRFC7515A1(t *testing.T) {
	v := rfc7515A1Verifier(t)

	h := make(map[string]any)
	var c jwt.RegisteredClaims
	err := jwt.Parse(rfc7515A1Token, h, &c, v, jwt.ParseOptions{
		ExpirationValidation: true,
		Time:                 time.Unix(1_300_819_379, 0),
	})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if h["alg"] != "HS256" {
		t.Errorf("alg = %q, want HS256", h["alg"])
	}
	if h["typ"] != "JWT" {
		t.Errorf("typ = %q, want JWT", h["typ"])
	}
	if c.Issuer != "joe" {
		t.Errorf("iss = %q, want joe", c.Issuer)
	}
	if c.Expiration != 1_300_819_380 {
		t.Errorf("exp = %d, want 1300819380", c.Expiration)
	}
}

// TestRFC7515A1Expired uses the same reference token past its expiry, so that
// the vector exercises the failing direction too.
func TestRFC7515A1Expired(t *testing.T) {
	v := rfc7515A1Verifier(t)

	var c jwt.RegisteredClaims
	err := jwt.Parse(rfc7515A1Token, nil, &c, v, jwt.ParseOptions{
		ExpirationValidation: true,
		Time:                 time.Unix(1_300_819_381, 0),
	})
	if err == nil {
		t.Fatal("Parse() accepted a token past its exp")
	}
}

// TestRFC7515A1WrongKey checks the reference token against a different secret.
func TestRFC7515A1WrongKey(t *testing.T) {
	other, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewHS256() error = %v", err)
	}

	if err := jwt.Parse(rfc7515A1Token, nil, nil, other, jwt.ParseOptions{}); err == nil {
		t.Fatal("Parse() accepted the reference token under a different key")
	}
}

// TestRFC7515A5Unsecured is the example from Appendix A.5: a token with
// "alg":"none" and an empty signature. The specification allows it and this
// package does not, deliberately, because a library that honours it hands an
// attacker a way to mint any claims at all.
func TestRFC7515A5Unsecured(t *testing.T) {
	const token = "eyJhbGciOiJub25lIn0." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	if err := jwt.Parse(token, nil, nil, rfc7515A1Verifier(t), jwt.ParseOptions{}); err == nil {
		t.Fatal("Parse() accepted an unsecured token")
	}
}

// TestGoldenToken pins the exact bytes this package produces for a fixed input.
// Where the RFC vector proves agreement with the specification, this one proves
// that a refactor did not silently change the encoding: field order, the base64
// alphabet, padding, the separator.
func TestGoldenToken(t *testing.T) {
	const want = "eyJhbGciOiJIUzI1NiJ9." +
		"eyJqdGkiOiJ0b2tlbi0xIiwiYXVkIjpbImFwaSJdLCJpc3MiOiJhdXRoIiwic3ViIjoidTEiLCJleHAiOjE3MDAwMDAwNjAsIm5iZiI6MTY5OTk5OTk0MCwiaWF0IjoxNzAwMDAwMDAwfQ." +
		"JJh_22I4G0er6s2On3J_xgDjJY9a5fk5hVDMpRbQ8oM"

	got, err := jwt.Sign(nil, &jwt.RegisteredClaims{
		ID:         "token-1",
		Audience:   jwt.Audience{"api"},
		Issuer:     "auth",
		Subject:    "u1",
		Expiration: 1_700_000_060,
		NotBefore:  1_699_999_940,
		IssuedAt:   1_700_000_000,
	}, testSigner(t))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if got != want {
		t.Errorf("the encoding changed.\n got %s\nwant %s", got, want)
	}
}

// The worked example from RFC 8037, Appendix A.4 and A.5: an Ed25519 key in JWK
// form and the compact token it produces.
//
// EdDSA is deterministic, so unlike the ECDSA vectors this one can be checked
// in both directions: the reference signature must verify, and signing the same
// input must reproduce it byte for byte.
//
// The payload is the text "Example of Ed25519 signing" rather than a JSON
// object, so Parse would rightly refuse it. The vector is used at the signer
// and verifier instead, which is where the interoperability actually lives.
const (
	rfc8037Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037PublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

	rfc8037Token = "eyJhbGciOiJFZERTQSJ9." +
		"RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc." +
		"hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)

func TestRFC8037A4(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	if err != nil {
		t.Fatalf("decoding the reference seed: %v", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(rfc8037PublicKey)
	if err != nil {
		t.Fatalf("decoding the reference public key: %v", err)
	}

	// The JWK carries the 32-byte seed; the standard library wants the 64-byte
	// expanded form, and derives the public half from it.
	priv := ed25519.NewKeyFromSeed(seed)
	if derived := priv.Public().(ed25519.PublicKey); !bytes.Equal(derived, pub) {
		t.Fatalf("the public key derived from the seed does not match the one published with it")
	}

	parts := strings.Split(rfc8037Token, ".")
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding the reference signature: %v", err)
	}

	t.Run("the reference signature verifies", func(t *testing.T) {
		v, err := jwt.NewEdDSAVerifier(pub)
		if err != nil {
			t.Fatalf("NewEdDSAVerifier() error = %v", err)
		}
		if err := v.Verify(signingInput, signature); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("signing reproduces it byte for byte", func(t *testing.T) {
		s, err := jwt.NewEdDSASigner(priv)
		if err != nil {
			t.Fatalf("NewEdDSASigner() error = %v", err)
		}
		got, err := s.Sign(signingInput)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if !bytes.Equal(got, signature) {
			t.Errorf("Sign() = %x\nwant        %x", got, signature)
		}
	})

	t.Run("a tampered payload is refused", func(t *testing.T) {
		v, err := jwt.NewEdDSAVerifier(pub)
		if err != nil {
			t.Fatalf("NewEdDSAVerifier() error = %v", err)
		}
		if err := v.Verify([]byte(parts[0]+".RXhhbXBsZSBvZiBFZDI1NTE4IHNpZ25pbmc"), signature); !errors.Is(err, jwt.ErrSignatureInvalid) {
			t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrSignatureInvalid)
		}
	})
}

// jwkInt decodes one base64url big-endian integer from a JWK.
func jwkInt(t *testing.T, s string) *big.Int {
	t.Helper()

	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}

	return new(big.Int).SetBytes(b)
}

// The worked example from RFC 7515, Appendix A.2: RS256, with the key given as
// a JWK, which is how keys travel between parties in practice.
//
// PKCS#1 v1.5 padding is deterministic, so this vector works in both
// directions: the published signature verifies, and signing the same input
// reproduces it byte for byte.
func TestRFC7515A2(t *testing.T) {
	const (
		n = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
			"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
			"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
			"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
			"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
			"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
		e = "AQAB"
		d = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
			"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
			"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
			"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
			"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
			"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
		p = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
			"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
			"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
		q = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
			"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
			"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"

		token = "eyJhbGciOiJSUzI1NiJ9." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
			"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
			"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
			"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
			"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
			"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
			"p0igcN_IoypGlUPQGe77Rw"
	)

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: jwkInt(t, n), E: int(jwkInt(t, e).Int64())},
		D:         jwkInt(t, d),
		Primes:    []*big.Int{jwkInt(t, p), jwkInt(t, q)},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		t.Fatalf("the reference key does not validate: %v", err)
	}

	parts := strings.Split(token, ".")
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding the reference signature: %v", err)
	}

	t.Run("the reference signature verifies", func(t *testing.T) {
		v, err := jwt.NewRS256Verifier(&key.PublicKey)
		if err != nil {
			t.Fatalf("NewRS256Verifier() error = %v", err)
		}
		if err := v.Verify(signingInput, signature); err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
	})

	t.Run("signing reproduces it byte for byte", func(t *testing.T) {
		s, err := jwt.NewRS256Signer(key)
		if err != nil {
			t.Fatalf("NewRS256Signer() error = %v", err)
		}
		got, err := s.Sign(signingInput)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if !bytes.Equal(got, signature) {
			t.Error("the signature differs from the one published with the vector")
		}
	})
}

// The worked example from RFC 7515, Appendix A.3: ES256.
//
// ECDSA draws a fresh nonce for every signature, so this one can only be
// checked in the verifying direction. Reproducing it is not possible and not
// expected.
func TestRFC7515A3(t *testing.T) {
	const (
		x     = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
		y     = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
		token = "eyJhbGciOiJFUzI1NiJ9." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
			"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	)

	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: jwkInt(t, x), Y: jwkInt(t, y)}

	parts := strings.Split(token, ".")
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding the reference signature: %v", err)
	}
	if len(signature) != 64 {
		t.Fatalf("the reference signature is %d bytes, want 64: two 32-byte halves", len(signature))
	}

	v, err := jwt.NewES256Verifier(pub)
	if err != nil {
		t.Fatalf("NewES256Verifier() error = %v", err)
	}
	if err := v.Verify(signingInput, signature); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	t.Run("a tampered signature is refused", func(t *testing.T) {
		bad := append([]byte{}, signature...)
		bad[0] ^= 0x01
		if err := v.Verify(signingInput, bad); !errors.Is(err, jwt.ErrSignatureInvalid) {
			t.Fatalf("Verify() error = %v, want %v", err, jwt.ErrSignatureInvalid)
		}
	})
}

// The worked example from RFC 7515, Appendix A.4: ES512, whose curve is P-521.
//
// This is the vector that catches the off-by-one nobody expects: a coordinate
// is 66 bytes because 521 bits does not divide by eight, so the signature is
// 132 rather than 128.
func TestRFC7515A4(t *testing.T) {
	const (
		x = "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_" +
			"NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"
		y = "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl" +
			"y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"
		token = "eyJhbGciOiJFUzUxMiJ9." +
			"UGF5bG9hZA." +
			"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq" +
			"wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp" +
			"EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
	)

	pub := &ecdsa.PublicKey{Curve: elliptic.P521(), X: jwkInt(t, x), Y: jwkInt(t, y)}

	parts := strings.Split(token, ".")
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding the reference signature: %v", err)
	}
	if len(signature) != 132 {
		t.Fatalf("the reference signature is %d bytes, want 132: two 66-byte halves", len(signature))
	}

	v, err := jwt.NewES512Verifier(pub)
	if err != nil {
		t.Fatalf("NewES512Verifier() error = %v", err)
	}
	if err := v.Verify(signingInput, signature); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}
