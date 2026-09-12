# jwt

A JSON Web Token library for Go, written against the RFCs with no external dependencies.

> **Status: v0.** Every signature algorithm in JOSE is implemented and the API is
> settling, but it has not been released yet.

**Scope: JWS only.** This package signs and verifies tokens (RFC 7515). It does not
implement JWE (encryption), and is not planned to. When people say "JWT" they almost
always mean JWS, and a JWS-only package is a complete JWT package for that purpose.

## Install

```bash
go get github.com/daanila01/jwt
```

## Quick start

Claims are whatever `encoding/json` accepts: your own struct, or a map when the
names are only known at run time. Embedding `jwt.RegisteredClaims` gives you the
registered fields and setters that take a `time.Time`.

The header is a `map[string]any`, because it holds three or four flat string
keys and nothing more. Pass `nil` when you have nothing to add: `alg` is written
from the signer either way, and overwrites whatever you put there, so a token
cannot claim an algorithm other than the one that signed it.

```go
package main

import (
	"fmt"
	"time"

	"github.com/daanila01/jwt"
)

type Claims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func main() {
	signer, err := jwt.NewHS256([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}

	claims := Claims{UserID: "u1", Role: "admin"}
	claims.SetExpiration(time.Now().Add(15 * time.Minute))

	token, err := jwt.Sign(nil, &claims, signer)
	if err != nil {
		panic(err)
	}

	var parsed Claims
	err = jwt.Parse(token, nil, &parsed, signer, jwt.ParseOptions{
		ExpirationValidation: true,
		ClockSkew:            30 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(parsed.UserID, parsed.Role)
}
```

Pass `nil` for the header when you do not need to read it, and `nil` for the claims when
you only want to know whether the token is authentic.

The two destinations are not shaped alike, because the data is not. A header map is
filled in place, so hand over one that has been made:

```go
header := map[string]any{}
err := jwt.Parse(token, header, &claims, verifier, jwt.ParseOptions{})
```

Claims follow the `encoding/json` rule instead: give a pointer, or there is nowhere to
write.

## Errors

Every failure is matched with `errors.Is` against a sentinel, so a caller can tell an
expired token from a forged one and answer accordingly.

```go
switch {
case errors.Is(err, jwt.ErrExpired):          // 401, tell the client to refresh
case errors.Is(err, jwt.ErrSignatureInvalid): // 401, and worth logging
case errors.Is(err, jwt.ErrTokenInvalid):     // 400, malformed input
}
```

| Sentinel | Meaning |
|---|---|
| `ErrTokenInvalid` | the token is malformed: shape, encoding, JSON, algorithm |
| `ErrSignatureInvalid` | well-formed, but not authentic |
| `ErrExpired` | `exp` has passed |
| `ErrNotYetValid` | `nbf` is in the future |
| `ErrClaimMissing` | a claim required by the enabled validation is absent |
| `ErrKeyInvalid` | the key does not fit the algorithm |
| `ErrArgumentInvalid` | a required argument was nil |

## Options

`ParseOptions` is a plain struct passed by value, and the zero value means defaults, so
`jwt.ParseOptions{}` is a valid call. Both options are variadic, so they can be left out
entirely. `SignOptions` carries nothing today: the header is yours to fill and the claims
are your own value, so there is nothing left for an option to reach.

| `ParseOptions` | Default | What it does |
|---|---|---|
| `MaxTokenSize` | 30 KB | rejected before any decoding, so a huge input costs nothing |
| `ExpirationValidation` | off | check `exp`; a token without one is rejected |
| `NotBeforeValidation` | off | check `nbf`; a token without one is rejected |
| `ExpectedIssuer` | none | the `iss` the token must carry, compared byte for byte |
| `ExpectedAudience` | none | this service's own name, which must appear in `aud` |
| `Time` | now | the moment to validate against, for tests |
| `ClockSkew` | 0 | tolerance for clocks that disagree between machines |

Validation of claims is opt-in. Signature verification is not: `Parse` always checks it.

## Algorithms

| Family | Algorithms | Key | Constructors |
|---|---|---|---|
| HMAC | HS256, HS384, HS512 | shared secret | `NewHS256` |
| EdDSA | EdDSA (Ed25519) | key pair | `NewEdDSASigner`, `NewEdDSAVerifier` |
| ECDSA | ES256, ES384, ES512 | key pair | `NewES256Signer`, `NewES256Verifier` |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | key pair | `NewRS256Signer`, `NewRS256Verifier` |
| RSA-PSS | PS256, PS384, PS512 | key pair | `NewPS256Signer`, `NewPS256Verifier` |

That is every signature algorithm JOSE registers, apart from ES256K on secp256k1,
which would mean a curve the standard library does not carry and a dependency this
package does not want.

HMAC is symmetric, so one value signs and verifies: anyone who can check a token can
also mint one. The rest split into two types on purpose, so that a service which only
verifies holds a key that cannot sign.

`none` is not supported and never will be. A token that declares it is rejected.

### What the numbers say

Cryptography only, without the JSON and base64 around it, on an Apple M1:

| Algorithm | Sign | Verify | Sign/sec | Verify/sec | Signature |
|---|---|---|---|---|---|
| HS256 | 0.3 µs | 0.3 µs | 3 100 000 | 3 000 000 | 32 B |
| HS384 | 0.7 µs | 0.7 µs | 1 400 000 | 1 300 000 | 48 B |
| HS512 | 0.7 µs | 0.7 µs | 1 400 000 | 1 300 000 | 64 B |
| EdDSA | 19.8 µs | 43.6 µs | 50 600 | 22 900 | 64 B |
| ES256 | 23.3 µs | 56.9 µs | 43 000 | 17 600 | 64 B |
| ES384 | 165.7 µs | 481.4 µs | 6 000 | 2 100 | 96 B |
| ES512 | 408.8 µs | 1310.9 µs | 2 400 | 760 | 132 B |
| RS256 | 1231.5 µs | 29.6 µs | 810 | 33 800 | 256 B |
| PS256 | 1217.8 µs | 30.1 µs | 820 | 33 200 | 256 B |

The two rate columns are one core each and come from the times beside them.

Read it as advice rather than trivia.

**HMAC is roughly seventy times faster than anything asymmetric.** When the issuer and
the verifier are the same service, nothing else is worth considering.

**EdDSA is the fastest asymmetric option and the safest to implement.** Its nonce is
derived from the key and the message instead of drawn at random, so the mistake that
broke the PlayStation 3 cannot be made. Prefer it whenever you control both ends.

**RSA signs a thousand times slower than it verifies.** That sounds fatal and is not:
one service issues tokens and a hundred check them, and on the checking side RSA is
quicker than EdDSA.

**ES384 and ES512 cost far more than their names suggest**, because P-256 has
hand-written assembly in the standard library and the larger curves do not. ES512 is
the slowest thing here in both directions.

A whole token costs more than the line above: signing a typical payload with HS256
takes about 1.5 µs and parsing it about 3.7, because most of that time is JSON and
base64 rather than the signature. On one core that is several hundred thousand tokens
a second.

Run `make bench` to get the figures for your own machine. The ones here come from one
laptop and are worth only what a single laptop is worth.

## Choosing an algorithm

```go
// issuer and verifier are the same service
signer, err := jwt.NewHS256(secret)

// separate parties: the issuer holds the private half
signer, err := jwt.NewES256Signer(privateKey)
verifier, err := jwt.NewES256Verifier(&privateKey.PublicKey)
```

A signer is built once, at startup, and shared: the constructor is where the key is
checked, and every implementation is safe for concurrent use. Building one per request
moves that check into the hot path and buys nothing.

Keys are rejected at construction rather than trusted at run time. An HMAC secret
shorter than the hash output, an RSA modulus under 2048 bits, an ECDSA key on the wrong
curve: each fails where you can see it, not on the first request in production.

## Verifying someone else's tokens

A service that checks tokens it did not issue faces two problems this package
answers separately.

The keys arrive as a JWK Set, not as PEM, which the standard library cannot read.
The `jwk` subpackage does:

```go
set, err := jwk.ParseSet(document) // document came from wherever you fetch it
```

And the issuer holds more than one key at a time, because rotating means
publishing the next one before retiring the last. The `kid` in a token's header
says which:

```go
err = jwt.Parse(token, nil, &claims, nil, jwt.ParseOptions{
	ResolveVerifier: func(h map[string]any) (jwt.Verifier, error) {
		kid, _ := h["kid"].(string)
		key, ok := set.ByID(kid)
		if !ok {
			return nil, fmt.Errorf("unknown key %q", kid)
		}
		return key.Verifier()
	},
})
```

Choose by `kid` and never by `alg`. The algorithm belongs to your record of the
key, not to the token: letting the token pick how it is checked is the whole of
the algorithm confusion attack. `Parse` still compares the header's `alg` against
whatever verifier comes back, so a resolver that follows this rule keeps that
protection and one that does not throws it away.

Fetching, caching and refreshing the document are not here, and will not be. Where
the bytes come from, how long they are trusted and what happens when the issuer is
unreachable are decisions only your service can make.

## Security

The known attacks against JWT libraries are closed by construction, not by configuration.

- **`alg: none` is rejected** explicitly, at header parse time.
- **The algorithm is never taken from the token.** You supply a `Verifier` that is pinned
  to one algorithm, and the token's `alg` is only compared against it. This is what stops
  algorithm confusion, where an RS256 token is re-signed with HS256 using the public key
  as the HMAC secret.
- **Signatures are compared in constant time**, so they cannot be recovered by timing.
- **The signature is verified before any claim is read.** Until it checks out, the payload
  is text an attacker sent you.
- **Keys are validated when the signer is created**, not on every call. A short HMAC key
  fails at startup rather than in production.
- **Input is size-capped before decoding**, and the parser does not panic on any input.

## Notes

Both destinations follow the `encoding/json` rule: pass a pointer, or there is nowhere to
write. `Parse` does not clear them first, it merges, so a field left by an earlier token
survives one that omits it. Pass a fresh value.

`Signer` and `Verifier` implementations are safe for concurrent use: build one at startup
and share it. The header and claims you pass in are not.

Claim validation is opt-in, signature verification is not. `Parse` always checks the
signature, and reads nothing from the claims until it holds.

## License

MIT
