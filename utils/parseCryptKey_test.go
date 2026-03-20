package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestParseCryptKey_ValidPEM(t *testing.T) {
	// Генерируем тестовый ключ
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	pemKey := string(pem.EncodeToMemory(pemBlock))

	result, err := ParseCryptKey(pemKey)
	if err != nil {
		t.Fatalf("ParseCryptKey() error = %v", err)
	}

	if !equalBytes(result, publicKeyDER) {
		t.Error("ParseCryptKey() result != expected public key")
	}
}

func TestParseCryptKey_ValidBase64(t *testing.T) {
	// Генерируем тестовый ключ
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	base64Key := base64.StdEncoding.EncodeToString(publicKeyDER)

	result, err := ParseCryptKey(base64Key)
	if err != nil {
		t.Fatalf("ParseCryptKey() error = %v", err)
	}

	if !equalBytes(result, publicKeyDER) {
		t.Error("ParseCryptKey() result != expected public key")
	}
}

func TestParseCryptKey_InvalidPEM(t *testing.T) {
	invalidPEM := "-----BEGIN PUBLIC KEY-----\nINVALID_DATA\n-----END PUBLIC KEY-----"

	_, err := ParseCryptKey(invalidPEM)
	if err == nil {
		t.Error("ParseCryptKey() expected error for invalid PEM")
	}
}

func TestParseCryptKey_InvalidBase64(t *testing.T) {
	invalidBase64 := "not_valid_base64!!!"

	_, err := ParseCryptKey(invalidBase64)
	if err == nil {
		t.Error("ParseCryptKey() expected error for invalid base64")
	}
}

func TestParseCryptKey_PEMWithAdditionalData(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	pemKey := string(pem.EncodeToMemory(pemBlock)) + "extra_data"

	_, err := ParseCryptKey(pemKey)
	if err == nil {
		t.Error("ParseCryptKey() expected error for PEM with additional data")
	}
}

func TestParseCryptKey_EmptyString(t *testing.T) {
	// Пустая строка валидно декодируется как пустой base64.
	result, err := ParseCryptKey("")
	if err != nil {
		t.Errorf("ParseCryptKey() unexpected error for empty string = %v", err)
	}
	if len(result) != 0 {
		t.Errorf("ParseCryptKey() expected empty result, got %d bytes", len(result))
	}
}

func TestParseCryptKey_Base64WithPadding(t *testing.T) {
	// Ключ, который требует padding в base64
	data := []byte("test key data")
	base64Key := base64.StdEncoding.EncodeToString(data)

	result, err := ParseCryptKey(base64Key)
	if err != nil {
		t.Fatalf("ParseCryptKey() error = %v", err)
	}

	if !equalBytes(result, data) {
		t.Error("ParseCryptKey() result != expected data")
	}
}

func TestParseCryptKey_Base64RawNoPadding(t *testing.T) {
	// Тест для base64 без padding (raw)
	// ParseCryptKey использует StdEncoding, который требует padding
	// Поэтому raw base64 без padding должен вернуть ошибку
	data := []byte("test")
	base64Raw := base64.RawStdEncoding.EncodeToString(data)

	_, err := ParseCryptKey(base64Raw)
	// Ожидаем ошибку, потому что StdEncoding требует padding
	if err == nil {
		t.Error("ParseCryptKey() expected error for raw base64 without padding")
	}
}

// equalBytes сравнивает два байтовых слайса
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
