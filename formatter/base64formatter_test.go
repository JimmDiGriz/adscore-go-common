package formatter

import (
	"encoding/base64"
	"testing"
)

func TestParse_BASE64_VARIANT_ORIGINAL(t *testing.T) {
	// "Hello, World!" в стандартном base64
	input := base64.StdEncoding.EncodeToString([]byte("Hello, World!"))

	result, err := Parse(input, "BASE64_VARIANT_ORIGINAL")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if string(result) != "Hello, World!" {
		t.Errorf("Parse() = %v, want %v", string(result), "Hello, World!")
	}
}

func TestParse_BASE64_VARIANT_ORIGINAL_NO_PADDING(t *testing.T) {
	// "Hello" в base64 без padding (длина кратна 3)
	input := base64.RawStdEncoding.EncodeToString([]byte("Hello"))

	result, err := Parse(input, "BASE64_VARIANT_ORIGINAL_NO_PADDING")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if string(result) != "Hello" {
		t.Errorf("Parse() = %v, want %v", string(result), "Hello")
	}
}

func TestParse_BASE64_VARIANT_URLSAFE(t *testing.T) {
	// Данные с символами, которые отличаются в URL-safe encoding
	input := base64.URLEncoding.EncodeToString([]byte("Hello+World/Test"))

	result, err := Parse(input, "BASE64_VARIANT_URLSAFE")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if string(result) != "Hello+World/Test" {
		t.Errorf("Parse() = %v, want %v", string(result), "Hello+World/Test")
	}
}

func TestParse_BASE64_VARIANT_URLSAFE_NO_PADDING(t *testing.T) {
	// "Hello" в URL-safe base64 без padding
	input := base64.RawURLEncoding.EncodeToString([]byte("Hello"))

	result, err := Parse(input, "BASE64_VARIANT_URLSAFE_NO_PADDING")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if string(result) != "Hello" {
		t.Errorf("Parse() = %v, want %v", string(result), "Hello")
	}
}

func TestParse_InvalidBase64(t *testing.T) {
	input := "invalid!!!base64"

	_, err := Parse(input, "BASE64_VARIANT_ORIGINAL")
	if err == nil {
		t.Error("Parse() expected error for invalid base64")
	}
}

func TestParse_UnsupportedFormat(t *testing.T) {
	input := "SGVsbG8="

	_, err := Parse(input, "UNSUPPORTED_FORMAT")
	if err == nil {
		t.Error("Parse() expected error for unsupported format")
	}
}

func TestParse_EmptyInput(t *testing.T) {
	result, err := Parse("", "BASE64_VARIANT_ORIGINAL")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Parse() expected empty result, got %d bytes", len(result))
	}
}

func TestParse_WithPadding(t *testing.T) {
	// Данные, требующие padding
	input := base64.StdEncoding.EncodeToString([]byte("test"))
	// input будет "dGVzdA=="

	result, err := Parse(input, "BASE64_VARIANT_ORIGINAL")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if string(result) != "test" {
		t.Errorf("Parse() = %v, want %v", string(result), "test")
	}
}

func TestParse_URLSafe_Vs_Original(t *testing.T) {
	// Данные, которые кодируются по-разному в URL-safe и standard
	data := []byte{0xFF, 0xFF, 0xFF} // Байты, которые дают '+' и '/' в standard

	original := base64.StdEncoding.EncodeToString(data)
	urlsafe := base64.URLEncoding.EncodeToString(data)

	// Original должен содержать '+' или '/'
	// URL-safe должен содержать '-' или '_'

	resultOrig, err := Parse(original, "BASE64_VARIANT_ORIGINAL")
	if err != nil {
		t.Fatalf("Parse() original error = %v", err)
	}

	resultURL, err := Parse(urlsafe, "BASE64_VARIANT_URLSAFE")
	if err != nil {
		t.Fatalf("Parse() urlsafe error = %v", err)
	}

	if string(resultOrig) != string(resultURL) {
		t.Error("Parse() original and urlsafe should decode to same data")
	}
}
