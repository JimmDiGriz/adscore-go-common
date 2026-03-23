package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	adscoreErrors "github.com/JimmDiGriz/adscore-go-common/adscoreErrors"
	utils "github.com/JimmDiGriz/adscore-go-common/utils"
)

var OpenSSLAEADMethod = 0x0201
var OpenSSLMethod = 0x0200
var tagLength = 16

func parse(payload []byte) (method int, iv []byte, tag []byte, data []byte, err error) {
	offset := 0

	if len(payload) < 2 {
		return -1, nil, nil, nil, adscoreErrors.NewParseError("premature end of signature")
	}

	methodUnpacked, err := utils.Unpack("vmethod", payload[0:2])

	if err != nil {
		return -1, nil, nil, nil, err
	}

	offset += 2
	method = *methodUnpacked["method"]

	ivLength := 16

	if method == OpenSSLAEADMethod {
		ivLength = 12
	}

	if len(payload) < offset+ivLength {
		return -1, nil, nil, nil, adscoreErrors.NewParseError("premature end of signature")
	}

	iv = payload[offset : offset+ivLength]

	offset += ivLength

	if method == OpenSSLAEADMethod {
		if len(payload) < offset+tagLength {
			return -1, nil, nil, nil, adscoreErrors.NewParseError("premature end of signature")
		}

		tag = payload[offset : offset+tagLength]
		offset += tagLength
	}

	data = payload[offset:]

	return method, iv, tag, data, nil

}

func DecryptSymmetricOpenSsl(payload []byte, encryptionKey []byte) ([]byte, error) {
	var method, iv, tag, data, err = parse(payload)

	if err != nil {
		return nil, err
	}

	// Обработка неизвестных методов шифрования
	if method != OpenSSLMethod && method != OpenSSLAEADMethod {
		return nil, adscoreErrors.NewParseError(
			fmt.Sprintf("unsupported encryption method: 0x%04x (supported: 0x0200=CBC, 0x0201=GCM)", method),
		)
	}

	if method == OpenSSLAEADMethod {
		return gcmDecrypt(data, encryptionKey, iv, tag)
	}
	return cbcDecrypt(data, encryptionKey, iv)
}

func cbcDecrypt(data []byte, encryptionKey []byte, iv []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, adscoreErrors.NewParseError("invalid CBC data length")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// Удаляем PKCS7 padding
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, adscoreErrors.NewParseError("invalid PKCS7 padding")
	}

	// Проверяем что все байты padding правильные
	for i := 0; i < padding; i++ {
		if data[len(data)-1-i] != byte(padding) {
			return nil, adscoreErrors.NewParseError("invalid PKCS7 padding")
		}
	}

	return data[:len(data)-padding], nil
}

func gcmDecrypt(data []byte, encryptionKey []byte, iv []byte, tag []byte) ([]byte, error) {
	// Клонируем data перед append, чтобы не мутировать входной слайс
	cipherText := append(append([]byte{}, data...), tag...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}

	result, err := mode.Open(nil, iv, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}
