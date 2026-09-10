# jwt

A JSON Web Token library for Go, written against the RFCs with no external dependencies.

> **Status: v0.** HS256 is implemented; the remaining algorithms and registered claims
> are on the way.

**Scope: JWS only.** This package signs and verifies tokens (RFC 7515). It does not
implement JWE (encryption), and is not planned to. When people say "JWT" they almost
always mean JWS, and a JWS-only package is a complete JWT package for that purpose.

## Install

```bash
go get github.com/daanila01/jwt
```

## Quick start

Claims are your own struct with `jwt.RegisteredClaims` embedded. There is no
`map[string]any` anywhere in the API, so your fields keep their types.

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

	token, err := jwt.Sign(nil, &Claims{UserID: "u1", Role: "admin"}, signer, jwt.SignOptions{
		Expiration: time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		panic(err)
	}

	var claims Claims
	err = jwt.Parse(token, nil, &claims, signer, jwt.ParseOptions{
		ExpirationValidation: true,
		ClockSkew:            30 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(claims.UserID, claims.Role)
}
```

Pass `nil` for the header when you do not need to read it. Pass `nil` for the claims too
when you only want to know whether the token is authentic.

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

`SignOptions` and `ParseOptions` are plain structs passed by value. The zero value means
defaults, so `jwt.ParseOptions{}` is a valid call.

| `ParseOptions` | Default | What it does |
|---|---|---|
| `MaxTokenSize` | 30 KB | rejected before any decoding, so a huge input costs nothing |
| `ExpirationValidation` | off | check `exp` |
| `NotBeforeValidation` | off | check `nbf` |
| `Time` | now | the moment to validate against, for tests |
| `ClockSkew` | 0 | tolerance for clocks that disagree between machines |

Validation of claims is opt-in. Signature verification is not: `Parse` always checks it.

## Algorithms

| Family | Algorithms | Status |
|---|---|---|
| HMAC | HS256, HS384, HS512 | HS256 done |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | planned |
| RSA-PSS | PS256, PS384, PS512 | planned |
| ECDSA | ES256, ES384, ES512 | planned |
| EdDSA | EdDSA (Ed25519) | planned |

`none` is not supported and never will be. A token that declares it is rejected.

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

`Parse` does not zero the destination struct. `encoding/json` merges into it, so fields
from a previous token survive. Pass a fresh value.

`Signer` and `Verifier` implementations are safe for concurrent use. The claims and header
values you pass in are not.

## License

MIT
