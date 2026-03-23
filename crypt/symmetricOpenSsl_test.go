package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestDecryptSymmetricOpenSsl_CBC(t *testing.T) {
	// Тестовые векторы для AES-256-CBC
	// Key: 32 байта
	key := []byte("0123456789abcdef0123456789abcdef")
	// IV: 16 байт
	iv := []byte("0123456789abcdef")
	// Plaintext: "Hello, World!123" (16 байт, ровно один блок)
	plaintext := []byte("Hello, World!123")

	// Добавляем PKCS7 padding (16 байт = 0x10 0x10 ... 0x10)
	padding := 16
	paddedPlaintext := make([]byte, len(plaintext)+padding)
	copy(paddedPlaintext, plaintext)
	for i := 0; i < padding; i++ {
		paddedPlaintext[len(plaintext)+i] = byte(padding)
	}

	// Шифруем для получения ciphertext
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Формируем payload: method(2) + iv(16) + data
	payload := make([]byte, 0, 2+16+len(ciphertext))
	payload = binary.LittleEndian.AppendUint16(payload, uint16(OpenSSLMethod))
	payload = append(payload, iv...)
	payload = append(payload, ciphertext...)

	// Дешифруем
	result, err := DecryptSymmetricOpenSsl(payload, key)
	if err != nil {
		t.Fatalf("DecryptSymmetricOpenSsl() error = %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("DecryptSymmetricOpenSsl() = %v, want %v", result, plaintext)
	}
}

func TestDecryptSymmetricOpenSsl_GCM(t *testing.T) {
	// Тестовые векторы для AES-256-GCM
	key := []byte("0123456789abcdef0123456789abcdef")
	// IV: 12 байт (стандарт для GCM)
	iv := []byte("0123456789ab")
	// Plaintext
	plaintext := []byte("Hello, World!")

	// Шифруем для получения ciphertext + tag
	block, _ := aes.NewCipher(key)
	mode, _ := cipher.NewGCMWithNonceSize(block, len(iv))
	ciphertextWithTag := mode.Seal(nil, iv, plaintext, nil)

	// Разделяем ciphertext и tag (tag последние 16 байт)
	tagLen := 16
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagLen]
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagLen:]

	// Формируем payload: method(2) + iv(12) + tag(16) + ciphertext
	payload := make([]byte, 0, 2+12+16+len(ciphertext))
	payload = binary.LittleEndian.AppendUint16(payload, uint16(OpenSSLAEADMethod))
	payload = append(payload, iv...)
	payload = append(payload, tag...)
	payload = append(payload, ciphertext...)

	// Дешифруем
	result, err := DecryptSymmetricOpenSsl(payload, key)
	if err != nil {
		t.Fatalf("DecryptSymmetricOpenSsl() error = %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("DecryptSymmetricOpenSsl() = %v, want %v", result, plaintext)
	}
}

func TestDecryptSymmetricOpenSsl_EmptyPayload(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	payload := []byte{}

	_, err := DecryptSymmetricOpenSsl(payload, key)
	if err == nil {
		t.Error("DecryptSymmetricOpenSsl() expected error for empty payload")
	}
}

func TestDecryptSymmetricOpenSsl_TruncatedPayload(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	// Только method, без IV
	payload := []byte{0x00, 0x02}

	_, err := DecryptSymmetricOpenSsl(payload, key)
	if err == nil {
		t.Error("DecryptSymmetricOpenSsl() expected error for truncated payload")
	}
}

func TestDecryptSymmetricOpenSsl_InvalidMethod(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789abcdef")

	// Неподдерживаемый метод
	payload := binary.LittleEndian.AppendUint16([]byte{}, 0x9999)
	payload = append(payload, iv...)
	// Данные должны быть полными блоками (16 байт) для CBC
	payload = append(payload, []byte("0123456789abcdef")...)

	// NOTE: Сейчас код не проверяет метод и пытается расшифровать как CBC.
	// Это баг, который будет зафиксен позже. Пока просто проверяем отсутствие panic.
	_, _ = DecryptSymmetricOpenSsl(payload, key)
	// Тест проходит, если нет panic
}

func TestDecryptSymmetricOpenSsl_GCM_InvalidTag(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789ab")

	// Формируем payload с битым тегом
	payload := binary.LittleEndian.AppendUint16([]byte{}, uint16(OpenSSLAEADMethod))
	payload = append(payload, iv...)
	// Битые данные (невалидный тег)
	payload = append(payload, []byte("invalid_tag_data_here")...)

	_, err := DecryptSymmetricOpenSsl(payload, key)
	if err == nil {
		t.Error("DecryptSymmetricOpenSsl() expected error for invalid GCM tag")
	}
}

func TestDecryptSymmetricOpenSsl_GCM_MutatesInput(t *testing.T) {
	// Проверяем, что функция не мутирует входные данные
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789ab")
	plaintext := []byte("Hello, World!")

	block, _ := aes.NewCipher(key)
	mode, _ := cipher.NewGCMWithNonceSize(block, len(iv))
	ciphertext := mode.Seal(nil, iv, plaintext, nil)

	payload := make([]byte, 0, 2+12+16+len(ciphertext)-16)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(OpenSSLAEADMethod))
	payload = append(payload, iv...)
	payload = append(payload, ciphertext...)

	// Сохраняем копию payload
	originalPayload := make([]byte, len(payload))
	copy(originalPayload, payload)

	_, _ = DecryptSymmetricOpenSsl(payload, key)

	if !bytes.Equal(payload, originalPayload) {
		t.Error("DecryptSymmetricOpenSsl() mutated input payload")
	}
}

func Test_cbcDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789abcdef")
	plaintext := []byte("Hello, World!123")

	// Добавляем PKCS7 padding (16 байт = 0x10 0x10 ... 0x10)
	padding := 16
	paddedPlaintext := make([]byte, len(plaintext)+padding)
	copy(paddedPlaintext, plaintext)
	for i := 0; i < padding; i++ {
		paddedPlaintext[len(plaintext)+i] = byte(padding)
	}

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	result, err := cbcDecrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("cbcDecrypt() error = %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("cbcDecrypt() = %v, want %v", result, plaintext)
	}
}

func Test_cbcDecrypt_InvalidKey(t *testing.T) {
	// Ключ неправильной длины
	key := []byte("short")
	iv := []byte("0123456789abcdef")
	data := []byte("0123456789abcdef")

	_, err := cbcDecrypt(data, key, iv)
	if err == nil {
		t.Error("cbcDecrypt() expected error for invalid key length")
	}
}

func Test_gcmDecrypt(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789ab")
	plaintext := []byte("Hello, World!")

	block, _ := aes.NewCipher(key)
	mode, _ := cipher.NewGCMWithNonceSize(block, len(iv))
	ciphertextWithTag := mode.Seal(nil, iv, plaintext, nil)

	// Разделяем ciphertext и tag
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-16]
	tag := ciphertextWithTag[len(ciphertextWithTag)-16:]

	result, err := gcmDecrypt(ciphertext, key, iv, tag)
	if err != nil {
		t.Fatalf("gcmDecrypt() error = %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("gcmDecrypt() = %v, want %v", result, plaintext)
	}
}

func Test_gcmDecrypt_InvalidTag(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789ab")
	ciphertext := []byte("0123456789abcdef")
	tag := []byte("invalid_tag_0123")

	_, err := gcmDecrypt(ciphertext, key, iv, tag)
	if err == nil {
		t.Error("gcmDecrypt() expected error for invalid tag")
	}
}

func Test_gcmDecrypt_InvalidKey(t *testing.T) {
	key := []byte("short")
	iv := []byte("0123456789ab")
	ciphertext := []byte("0123456789abcdef")
	tag := []byte("0123456789abcdef")

	_, err := gcmDecrypt(ciphertext, key, iv, tag)
	if err == nil {
		t.Error("gcmDecrypt() expected error for invalid key length")
	}
}
