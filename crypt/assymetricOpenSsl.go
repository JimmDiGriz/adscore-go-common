package crypt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// VerifyAsymmetricError возвращается при ошибке верификации подписи
type VerifyAsymmetricError struct {
	message string
}

func (e *VerifyAsymmetricError) Error() string {
	return e.message
}

// VerifyAsymmetric проверяет ECDSA подпись.
// Возвращает (true, nil) если подпись валидна, (false, error) если нет.
func VerifyAsymmetric(data []byte, signature []byte, cryptKey []byte) (bool, error) {
	publicKeyInterface, err := x509.ParsePKIXPublicKey(cryptKey)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKeyECDSA, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("public key is not ECDSA")
	}

	hash := sha256.Sum256(data)

	valid := ecdsa.VerifyASN1(publicKeyECDSA, hash[:], signature)
	if !valid {
		return false, &VerifyAsymmetricError{message: "signature verification failed"}
	}

	return true, nil
}
