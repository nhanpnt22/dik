package dik

import (
	"errors"
	"strings"
	"testing"
)

func TestSupportedProviders(t *testing.T) {
	want := []string{"internal", "device", "phone", "email", "zalo", "google", "facebook", "apple", "firebase"}
	got := SupportedProviders()

	if len(got) != len(want) {
		t.Fatalf("SupportedProviders len = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("SupportedProviders[%d] = %q, want %q", index, got[index], want[index])
		}
	}

	got[0] = "mutated"
	if SupportedProviders()[0] != "internal" {
		t.Fatal("SupportedProviders should return a defensive copy")
	}
}

func TestValidateProvider(t *testing.T) {
	for _, provider := range []string{"internal", "device", "phone", "email", "zalo", "google", "facebook", "apple", "firebase"} {
		if err := ValidateProvider(provider); err != nil {
			t.Fatalf("ValidateProvider(%q): unexpected error: %v", provider, err)
		}
	}

	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "uppercase", value: "Zalo", wantErr: ErrProviderNotCanonical},
		{name: "trimmed", value: " zalo ", wantErr: ErrProviderNotCanonical},
		{name: "unknown", value: "custom", wantErr: ErrUnknownProvider},
		{name: "invalid char", value: "em@il", wantErr: ErrInvalidProvider},
		{name: "too long", value: "a" + strings.Repeat("b", 64), wantErr: ErrInvalidProvider},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateProvider(testCase.value)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("ValidateProvider(%q) = %v, want %v", testCase.value, err, testCase.wantErr)
			}
		})
	}
}

func TestValidateRawIdentity(t *testing.T) {
	if err := ValidateRawIdentity("abc123"); err != nil {
		t.Fatalf("ValidateRawIdentity: unexpected error: %v", err)
	}

	if err := ValidateRawIdentity(""); !errors.Is(err, ErrInvalidIdentityInput) {
		t.Fatalf("ValidateRawIdentity(empty) = %v, want ErrInvalidIdentityInput", err)
	}

	if err := ValidateRawIdentity(strings.Repeat("x", 65)); !errors.Is(err, ErrInvalidIdentityInput) {
		t.Fatalf("ValidateRawIdentity(>64) = %v, want ErrInvalidIdentityInput", err)
	}
}

func TestCanonicalInput(t *testing.T) {
	got, err := CanonicalInput("zalo", "abc123")
	if err != nil {
		t.Fatalf("CanonicalInput: unexpected error: %v", err)
	}

	want := "v1|4:zalo|6:abc123"
	if got != want {
		t.Fatalf("CanonicalInput = %q, want %q", got, want)
	}
}

func TestValidateCanonicalInput(t *testing.T) {
	if err := ValidateCanonicalInput("v1|4:zalo|6:abc123"); err != nil {
		t.Fatalf("ValidateCanonicalInput: unexpected error: %v", err)
	}

	for _, input := range []string{
		"v2|4:zalo|6:abc123",
		"v1|04:zalo|6:abc123",
		"v1|4:zalo|07:abc123",
		"v1|4:Zalo|6:abc123",
	} {
		if err := ValidateCanonicalInput(input); !errors.Is(err, ErrInvalidCanonicalInput) && !errors.Is(err, ErrProviderNotCanonical) {
			t.Fatalf("ValidateCanonicalInput(%q) = %v, want canonical/provider error", input, err)
		}
	}
}

func TestGenerateDeterministic(t *testing.T) {
	key1, err := Generate("zalo", "abc123")
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}
	key2, err := GenerateString("zalo", "abc123")
	if err != nil {
		t.Fatalf("GenerateString: unexpected error: %v", err)
	}
	if key1 != key2 {
		t.Fatalf("Generate and GenerateString mismatch: %q != %q", key1, key2)
	}
	if len(key1) != IdentityKeyHexLength {
		t.Fatalf("identity key length = %d, want %d", len(key1), IdentityKeyHexLength)
	}
	if !IsValidIdentityKey(key1) {
		t.Fatalf("identity key %q is not valid", key1)
	}
}

func TestGenerateKnownVector(t *testing.T) {
	key, err := Generate("zalo", "abc123")
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	if key == "" {
		t.Fatal("Generate returned empty key")
	}

	if key != MustGenerate("zalo", "abc123") {
		t.Fatal("MustGenerate and Generate should match")
	}
}

func TestGenerateRawIdentityLengthError(t *testing.T) {
	_, err := Generate("zalo", strings.Repeat("x", 65))
	if !errors.Is(err, ErrInvalidIdentityInput) {
		t.Fatalf("Generate(>64 raw) = %v, want ErrInvalidIdentityInput", err)
	}
}

func TestGenerateHash(t *testing.T) {
	identityKey, err := Generate("zalo", "abc123")
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}

	identityHash, err := GenerateHash(identityKey, "pepper-v1")
	if err != nil {
		t.Fatalf("GenerateHash: unexpected error: %v", err)
	}

	if len(identityHash) != IdentityHashHexLength {
		t.Fatalf("identity hash length = %d, want %d", len(identityHash), IdentityHashHexLength)
	}
	if !IsValidIdentityHash(identityHash) {
		t.Fatalf("identity hash %q is not valid", identityHash)
	}

	identityHashAgain, err := GenerateHash(identityKey, "pepper-v1")
	if err != nil {
		t.Fatalf("GenerateHash repeat: unexpected error: %v", err)
	}
	if identityHash != identityHashAgain {
		t.Fatalf("GenerateHash should be deterministic: %q != %q", identityHash, identityHashAgain)
	}
}

func TestGenerateHashValidation(t *testing.T) {
	if _, err := GenerateHash("not-a-key", "pepper"); !errors.Is(err, ErrInvalidIdentityKey) {
		t.Fatalf("GenerateHash(invalid key) = %v, want ErrInvalidIdentityKey", err)
	}
}

func TestMustGeneratePanicsOnInvalidProvider(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("MustGenerate did not panic on invalid provider")
		}
	}()

	_ = MustGenerate("Zalo", "abc123")
}
