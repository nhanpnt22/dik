// Package dik generates and validates Deterministic Identity Keys (DIK).
//
// DIK is a stateless, deterministic identity primitive derived from the
// canonical (provider, raw_identity) input pair defined by the AIP DIK and DIP
// specs.
//
// Canonical flow:
//
//	v1|len(provider):provider|len(raw_identity):raw_identity
//	-> BLAKE3 128-bit
//	-> lowercase hex identity_key
//
// The optional external identity hash uses a peppered BLAKE3 256-bit hash of
// the internal identity key and is safe for exposure.
package dik

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"lukechampine.com/blake3"
)

const (
	// ProtocolVersion is the locked DIK protocol version embedded in canonical input.
	ProtocolVersion = "v1"

	// CanonicalPrefix is the required version prefix for canonical DIK input.
	CanonicalPrefix = ProtocolVersion + "|"

	// IdentityKeyHexLength is the encoded length of a 128-bit BLAKE3 output.
	IdentityKeyHexLength = 32

	// IdentityHashHexLength is the encoded length of a 256-bit BLAKE3 output.
	IdentityHashHexLength = 64

	// MaxProviderLength matches the locked provider registry contract.
	MaxProviderLength = 64

	// MaxRawIdentityLength is the DIK raw identity byte limit.
	MaxRawIdentityLength = 64

	// HashCollisionErrorCode is the canonical failure code for a detected collision.
	HashCollisionErrorCode = "HASH_COLLISION_DETECTED"
)

var (
	providerPattern     = regexp.MustCompile(`^[a-z][a-z0-9_+.-]{0,63}$`)
	identityKeyPattern  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	identityHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

	supportedProviders = []string{
		"internal",
		"device",
		"phone",
		"email",
		"zalo",
		"google",
		"facebook",
		"apple",
		"firebase",
	}

	providerRegistry = map[string]struct{}{
		"internal": {},
		"device":   {},
		"phone":    {},
		"email":    {},
		"zalo":     {},
		"google":   {},
		"facebook": {},
		"apple":    {},
		"firebase": {},
	}

	ErrInvalidProvider       = errors.New("dik: invalid provider")
	ErrUnknownProvider       = errors.New("dik: unknown provider")
	ErrProviderNotCanonical  = errors.New("dik: provider is not canonical")
	ErrInvalidIdentityInput  = errors.New("dik: invalid identity input")
	ErrInvalidCanonicalInput = errors.New("dik: invalid canonical format")
	ErrInvalidIdentityKey    = errors.New("dik: invalid identity key")
	ErrInvalidIdentityHash   = errors.New("dik: invalid identity hash")
	ErrHashCollisionDetected = errors.New("dik: hash collision detected")
)

// SupportedProviders returns the locked provider registry in canonical order.
func SupportedProviders() []string {
	providers := make([]string, len(supportedProviders))
	copy(providers, supportedProviders)
	return providers
}

// IsSupportedProvider reports whether provider is present in the locked registry.
func IsSupportedProvider(provider string) bool {
	_, ok := providerRegistry[provider]
	return ok
}

// ValidateProvider checks the provider against the locked DIP registry.
func ValidateProvider(provider string) error {
	if strings.TrimSpace(provider) != provider || strings.ToLower(provider) != provider {
		return fmt.Errorf("%w: %q", ErrProviderNotCanonical, provider)
	}
	if len(provider) == 0 || len(provider) > MaxProviderLength || !providerPattern.MatchString(provider) {
		return fmt.Errorf("%w: %q", ErrInvalidProvider, provider)
	}
	if !IsSupportedProvider(provider) {
		return fmt.Errorf("%w: %q", ErrUnknownProvider, provider)
	}

	return nil
}

// ValidateRawIdentity checks the transient raw identity input against the DIK contract.
func ValidateRawIdentity(rawIdentity string) error {
	if len(rawIdentity) == 0 || len(rawIdentity) > MaxRawIdentityLength {
		return fmt.Errorf("%w: raw_identity byte length must be 1..%d", ErrInvalidIdentityInput, MaxRawIdentityLength)
	}

	return nil
}

// ValidateIdentityKey checks that value is a 32-character lowercase hex identity key.
func ValidateIdentityKey(identityKey string) error {
	if !identityKeyPattern.MatchString(identityKey) {
		return fmt.Errorf("%w: %q", ErrInvalidIdentityKey, identityKey)
	}

	return nil
}

// ValidateIdentityHash checks that value is a 64-character lowercase hex identity hash.
func ValidateIdentityHash(identityHash string) error {
	if !identityHashPattern.MatchString(identityHash) {
		return fmt.Errorf("%w: %q", ErrInvalidIdentityHash, identityHash)
	}

	return nil
}

// CanonicalInput builds the locked DIK canonical input string.
func CanonicalInput(provider, rawIdentity string) (string, error) {
	if err := ValidateProvider(provider); err != nil {
		return "", err
	}
	if err := ValidateRawIdentity(rawIdentity); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%d:%s|%d:%s", CanonicalPrefix, len(provider), provider, len(rawIdentity), rawIdentity), nil
}

// ValidateCanonicalInput verifies that canonicalInput exactly matches the locked
// v1 canonical encoding, including byte lengths and provider/raw identity values.
func ValidateCanonicalInput(canonicalInput string) error {
	if !strings.HasPrefix(canonicalInput, CanonicalPrefix) {
		return fmt.Errorf("%w: missing %q prefix", ErrInvalidCanonicalInput, CanonicalPrefix)
	}

	remaining := strings.TrimPrefix(canonicalInput, CanonicalPrefix)
	providerLenText, afterProviderLen, ok := strings.Cut(remaining, ":")
	if !ok || providerLenText == "" {
		return fmt.Errorf("%w: invalid provider length segment", ErrInvalidCanonicalInput)
	}
	providerLen, err := strconv.Atoi(providerLenText)
	if err != nil || providerLen < 0 {
		return fmt.Errorf("%w: invalid provider length %q", ErrInvalidCanonicalInput, providerLenText)
	}

	provider, afterProvider, ok := strings.Cut(afterProviderLen, "|")
	if !ok {
		return fmt.Errorf("%w: missing provider/raw separator", ErrInvalidCanonicalInput)
	}
	if len(provider) != providerLen {
		return fmt.Errorf("%w: provider length mismatch", ErrInvalidCanonicalInput)
	}

	rawLenText, rawIdentity, ok := strings.Cut(afterProvider, ":")
	if !ok || rawLenText == "" {
		return fmt.Errorf("%w: invalid raw_identity length segment", ErrInvalidCanonicalInput)
	}
	rawLen, err := strconv.Atoi(rawLenText)
	if err != nil || rawLen < 0 {
		return fmt.Errorf("%w: invalid raw_identity length %q", ErrInvalidCanonicalInput, rawLenText)
	}
	if len(rawIdentity) != rawLen {
		return fmt.Errorf("%w: raw_identity length mismatch", ErrInvalidCanonicalInput)
	}

	canonical, err := CanonicalInput(provider, rawIdentity)
	if err != nil {
		return err
	}
	if canonical != canonicalInput {
		return fmt.Errorf("%w: canonical input must match exact locked encoding", ErrInvalidCanonicalInput)
	}

	return nil
}

// GenerateFromCanonicalInput hashes a locked canonical input string into a DIK.
func GenerateFromCanonicalInput(canonicalInput string) (string, error) {
	if err := ValidateCanonicalInput(canonicalInput); err != nil {
		return "", err
	}

	hasher := blake3.New(IdentityKeyHexLength/2, nil)
	if _, err := hasher.Write([]byte(canonicalInput)); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidIdentityInput, err)
	}

	digest := hasher.Sum(nil)
	if len(digest) != IdentityKeyHexLength/2 {
		return "", fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidIdentityKey, len(digest), IdentityKeyHexLength/2)
	}

	identityKey := hex.EncodeToString(digest)
	if err := ValidateIdentityKey(identityKey); err != nil {
		return "", err
	}

	return identityKey, nil
}

// Generate hashes provider and rawIdentity into a deterministic DIK identity key.
func Generate(provider, rawIdentity string) (string, error) {
	canonicalInput, err := CanonicalInput(provider, rawIdentity)
	if err != nil {
		return "", err
	}

	return GenerateFromCanonicalInput(canonicalInput)
}

// GenerateString is a convenience wrapper around Generate for string inputs.
func GenerateString(provider, rawIdentity string) (string, error) {
	return Generate(provider, rawIdentity)
}

// MustGenerate is like Generate but panics on error.
func MustGenerate(provider, rawIdentity string) string {
	value, err := Generate(provider, rawIdentity)
	if err != nil {
		panic(err)
	}

	return value
}

// GenerateHash returns the peppered external-safe identity hash.
func GenerateHash(identityKey, identityPepper string) (string, error) {
	if err := ValidateIdentityKey(identityKey); err != nil {
		return "", err
	}

	payload := fmt.Sprintf("%d:%s|%d:%s", len(identityKey), identityKey, len(identityPepper), identityPepper)
	digest := blake3.Sum256([]byte(payload))
	identityHash := hex.EncodeToString(digest[:])
	if err := ValidateIdentityHash(identityHash); err != nil {
		return "", err
	}

	return identityHash, nil
}

// MustGenerateHash is like GenerateHash but panics on error.
func MustGenerateHash(identityKey, identityPepper string) string {
	value, err := GenerateHash(identityKey, identityPepper)
	if err != nil {
		panic(err)
	}

	return value
}

// IsValidProvider reports whether provider is canonical and present in the registry.
func IsValidProvider(provider string) bool {
	return ValidateProvider(provider) == nil
}

// IsValidIdentityKey reports whether the value is a valid 32-character lowercase hex key.
func IsValidIdentityKey(identityKey string) bool {
	return ValidateIdentityKey(identityKey) == nil
}

// IsValidIdentityHash reports whether the value is a valid 64-character lowercase hex hash.
func IsValidIdentityHash(identityHash string) bool {
	return ValidateIdentityHash(identityHash) == nil
}
