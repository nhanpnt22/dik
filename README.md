# dik

Deterministic Identity Key utilities for the AIP DIK and DIP specs.

## Install

```sh
go get github.com/nhanpnt22/dik
```

## Import

```go
import "github.com/nhanpnt22/dik"
```

## Canonical flow

```text
v1|len(provider):provider|len(raw_identity):raw_identity
-> BLAKE3 128-bit
-> lowercase hex identity_key
```

## API

```go
func Generate(provider, rawIdentity string) (string, error)
func MustGenerate(provider, rawIdentity string) string
func GenerateString(provider, rawIdentity string) (string, error)
func GenerateFromCanonicalInput(canonicalInput string) (string, error)
func GenerateHash(identityKey, identityPepper string) (string, error)
func MustGenerateHash(identityKey, identityPepper string) string
func CanonicalInput(provider, rawIdentity string) (string, error)
func ValidateProvider(provider string) error
func ValidateRawIdentity(rawIdentity string) error
func ValidateCanonicalInput(canonicalInput string) error
func ValidateIdentityKey(identityKey string) error
func ValidateIdentityHash(identityHash string) error
func SupportedProviders() []string
func IsSupportedProvider(provider string) bool
func IsValidProvider(provider string) bool
func IsValidIdentityKey(identityKey string) bool
func IsValidIdentityHash(identityHash string) bool
```

## Registry

Locked providers:

- internal
- device
- phone
- email
- zalo
- google
- facebook
- apple
- firebase
# dik
