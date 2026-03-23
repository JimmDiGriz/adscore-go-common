package crypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// generateTestKeyPair создаёт тестовую пару ключей ECDSA P-256
func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateTestKeyPair() error = %v", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("generateTestKeyPair() marshal error = %v", err)
	}

	return privateKey, publicKeyDER
}

func TestVerifyAsymmetric_Valid(t *testing.T) {
	privateKey, publicKeyDER := generateTestKeyPair(t)

	data := []byte("Hello, World!")
	hash := sha256.Sum256(data)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("TestVerifyAsymmetric_Valid() sign error = %v", err)
	}

	result, err := VerifyAsymmetric(data, signature, publicKeyDER)
	if err != nil {
		t.Fatalf("VerifyAsymmetric() error = %v", err)
	}

	if !result {
		t.Error("VerifyAsymmetric() = false, want true for valid signature")
	}
}

func TestVerifyAsymmetric_InvalidSignature(t *testing.T) {
	_, publicKeyDER := generateTestKeyPair(t)

	data := []byte("Hello, World!")
	// Поддельная подпись
	signature := []byte("invalid_signature_data")

	result, err := VerifyAsymmetric(data, signature, publicKeyDER)
	if err == nil {
		t.Error("VerifyAsymmetric() expected error for invalid signature format")
	}

	if result {
		t.Error("VerifyAsymmetric() = true, want false for invalid signature")
	}
}

func TestVerifyAsymmetric_TamperedData(t *testing.T) {
	privateKey, publicKeyDER := generateTestKeyPair(t)

	data := []byte("Hello, World!")
	hash := sha256.Sum256(data)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("TestVerifyAsymmetric_TamperedData() sign error = %v", err)
	}

	// Изменяем данные
	tamperedData := []byte("Tampered World!")

	result, err := VerifyAsymmetric(tamperedData, signature, publicKeyDER)
	if err == nil {
		t.Error("VerifyAsymmetric() expected error for tampered data")
	}

	if result {
		t.Error("VerifyAsymmetric() = true, want false for tampered data")
	}
}

func TestVerifyAsymmetric_InvalidKey(t *testing.T) {
	data := []byte("Hello, World!")
	signature := []byte("signature")
	invalidKey := []byte("not a valid public key")

	result, err := VerifyAsymmetric(data, signature, invalidKey)
	if err == nil {
		t.Error("VerifyAsymmetric() expected error for invalid key")
	}

	if result {
		t.Error("VerifyAsymmetric() = true, want false for invalid key")
	}
}

func TestVerifyAsymmetric_EmptyData(t *testing.T) {
	privateKey, publicKeyDER := generateTestKeyPair(t)

	data := []byte{}
	hash := sha256.Sum256(data)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("TestVerifyAsymmetric_EmptyData() sign error = %v", err)
	}

	result, err := VerifyAsymmetric(data, signature, publicKeyDER)
	if err != nil {
		t.Fatalf("VerifyAsymmetric() error = %v", err)
	}

	if !result {
		t.Error("VerifyAsymmetric() = false, want true for empty data")
	}
}

func TestVerifyAsymmetric_PEMKey(t *testing.T) {
	privateKey, publicKeyDER := generateTestKeyPair(t)

	// Кодируем ключ в PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}
	pemKey := pem.EncodeToMemory(pemBlock)

	data := []byte("Hello, World!")
	hash := sha256.Sum256(data)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("TestVerifyAsymmetric_PEMKey() sign error = %v", err)
	}

	// VerifyAsymmetric ожидает DER, а не PEM — это должно вернуть ошибку
	result, err := VerifyAsymmetric(data, signature, pemKey)
	if err == nil {
		t.Error("VerifyAsymmetric() expected error for PEM-encoded key")
	}

	if result {
		t.Error("VerifyAsymmetric() = true, want false for PEM-encoded key")
	}
}

func TestVerifyAsymmetric_WrongKey(t *testing.T) {
	// Создаём две разные пары ключей
	privateKey1, _ := generateTestKeyPair(t)
	_, publicKeyDER2 := generateTestKeyPair(t)

	data := []byte("Hello, World!")
	hash := sha256.Sum256(data)

	signature, err := ecdsa.SignASN1(rand.Reader, privateKey1, hash[:])
	if err != nil {
		t.Fatalf("TestVerifyAsymmetric_WrongKey() sign error = %v", err)
	}

	// Проверяем подписью от key1 с ключом key2 — должна быть ошибка верификации
	result, err := VerifyAsymmetric(data, signature, publicKeyDER2)
	if err == nil {
		t.Error("VerifyAsymmetric() expected error for wrong key")
	}

	if result {
		t.Error("VerifyAsymmetric() = true, want false for wrong key")
	}
}
