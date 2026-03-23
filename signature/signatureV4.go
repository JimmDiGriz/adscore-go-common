package adscoreSignature

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"

	adscoreErrors "github.com/JimmDiGriz/adscore-go-common/adscoreErrors"
	adscoreCrypt "github.com/JimmDiGriz/adscore-go-common/crypt"
	formatter "github.com/JimmDiGriz/adscore-go-common/formatter"
	judge "github.com/JimmDiGriz/adscore-go-common/judge"
	utils "github.com/JimmDiGriz/adscore-go-common/utils"
)

const SUPPORTED_VERSION_V4 = 4
const HASH_SHA256 = 1
const SIGN_SHA256 = 2

type Signature4 struct {
	VERSION          int
	ZoneId           int64
	Payload          SignaturePayload
	VerificationData SignaturePayload
	Result           int
}

type FieldTypeDef struct {
	Name string
	Type string
}

var FIELD_IDS = map[uint8]*FieldTypeDef{
	0x00: {"requestTime", "ulong"},
	0x01: {"signatureTime", "ulong"},
	0x10: {"ipv4", "ulong"},    // Debug field
	0x40: {"pizdec", "ushort"}, // Reserved for future use
	0x80: {"masterSignType", "uchar"},
	0x81: {"customerSignType", "uchar"},
	0xc0: {"masterToken", "string"},
	0xc1: {"customerToken", "string"},
	0xc2: {"masterToken6", "string"},
	0xc3: {"customerToken6", "string"},
	0xc4: {"ipv6", "string"},
	0xc5: {"masterChecksum", "string"},
	0xd0: {"userAgent", "string"}, // Debug field,
}

type SimpleType struct {
	unpack string
	size   int
}

var SIMPLE_TYPES = map[string]*SimpleType{
	"uchar":  {unpack: "Cx/Cv", size: 2},
	"ushort": {unpack: "Cx/nv", size: 3},
	"ulong":  {unpack: "Cx/Nv", size: 5},
	"string": {unpack: "Cx/nv", size: 3 /* + length(value) */},
}

func CreateSignatureV4FromRequest(signature string, ipAddresses []string, userAgent string, cryptKey string) (*Signature4, error) {
	if len(signature) == 0 {
		return nil, adscoreErrors.NewParseError("premature end of signature")
	}

	parsedCryptKey, err := utils.ParseCryptKey(cryptKey)

	if err != nil {
		return nil, err
	}

	obj := &Signature4{
		VERSION: SUPPORTED_VERSION_V4,
	}

	err = obj.parse(signature, "BASE64_VARIANT_URLSAFE_NO_PADDING")

	if err != nil {
		return nil, err
	}

	err = obj.verify(ipAddresses, userAgent, parsedCryptKey, "customer")

	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *Signature4) parse(signature string, format string) error {
	encryptedPayload, payloadDecodeError := formatter.Parse(signature, format)

	if payloadDecodeError != nil {
		return payloadDecodeError
	}

	var data, payloadUnpackError = utils.Unpack("Cversion/CfieldNum", encryptedPayload)

	if payloadUnpackError != nil {
		return payloadUnpackError
	}

	if int(*data["version"]) != SUPPORTED_VERSION_V4 {
		return adscoreErrors.NewVersionError("signature version not supported")
	}

	encryptedPayload = encryptedPayload[2:]

	s.Payload = map[string]interface{}{}

	for i := 0; i < int(*data["fieldNum"]); i++ {

		var fieldIdData, fieldIdError = utils.Unpack("CfieldId", encryptedPayload)

		if fieldIdError != nil {
			return fieldIdError
		}

		if fieldIdData["fieldId"] == nil {
			return adscoreErrors.NewParseError("premature end of signature")
		}

		var fieldId = uint8(*fieldIdData["fieldId"])

		// Fix #6: Безопасная обработка неизвестных fieldId
		var fieldTypeDef *FieldTypeDef
		if FIELD_IDS[fieldId] != nil {
			fieldTypeDef = FIELD_IDS[fieldId]
		} else {
			highBits := fieldId & 0xc0
			if FIELD_IDS[highBits] == nil {
				return adscoreErrors.NewParseError(fmt.Sprintf("unknown field ID 0x%02x", fieldId))
			}
			t := FIELD_IDS[highBits].Type
			/* Guess field size, but leave unrecognized */
			fieldTypeDef = &FieldTypeDef{
				Type: t,
				Name: fmt.Sprintf("%s%02x", t, i),
			}
		}

		if fieldTypeDef.Name == "" || fieldTypeDef.Type == "" {
			return adscoreErrors.NewParseError("invalid Field ID")
		}

		var readData, newSignature, err = readStructureField(encryptedPayload, fieldTypeDef.Type)

		if err != nil {
			return err
		}

		encryptedPayload = newSignature

		s.Payload[fieldTypeDef.Name] = readData
	}

	return nil
}

func (s *Signature4) verify(ipAddresses []string, userAgent string, cryptKey []byte, signRole string) error {
	if signRole != "customer" && signRole != "master" {
		return adscoreErrors.NewParseError("unsupported signRole")
	}

	// Fix #2: Проверяем наличие полей перед type assertion
	signTypeVal, ok := s.Payload[signRole+"SignType"].(*int)
	if !ok {
		return adscoreErrors.NewParseError("missing " + signRole + "SignType")
	}

	for _, ipAddress := range ipAddresses {
		providedIpAddress := net.ParseIP(ipAddress)
		v := 4

		var token []byte
		if providedIpAddress.To4() != nil {
			tokenVal, ok := s.Payload[signRole+"Token"].([]byte)
			if !ok {
				return adscoreErrors.NewParseError("missing " + signRole + "Token")
			}
			token = tokenVal
		} else if providedIpAddress.To16() != nil {
			v = 6
			tokenVal, ok := s.Payload[signRole+"Token6"].([]byte)
			if !ok || tokenVal == nil {
				continue
			}
			token = tokenVal
		}

		// Проверяем наличие requestTime и signatureTime
		requestTimeVal, ok := s.Payload["requestTime"].(*int)
		if !ok {
			return adscoreErrors.NewParseError("missing requestTime")
		}
		signatureTimeVal, ok := s.Payload["signatureTime"].(*int)
		if !ok {
			return adscoreErrors.NewParseError("missing signatureTime")
		}

		/* Check all possible results */
		for result := range judge.Judge {
			meta := judge.RESULTS[result]

			signatureBase := getHashBase(result, requestTimeVal, signatureTimeVal, ipAddress, userAgent)

			switch *signTypeVal {
			case HASH_SHA256:
				if verifyHashedSignature(signatureBase, cryptKey, token) {
					s.VerificationData = SignaturePayload{}
					s.VerificationData["verdict"] = meta.Verdict
					s.VerificationData["result"] = result
					s.VerificationData["ipv"+strconv.Itoa(v)+"ip"] = ipAddress
					s.VerificationData[""] = verifyEmbeddedIpv6(s.Payload, result, cryptKey, userAgent, signRole)
					s.Result = result

					return nil
				}

			case SIGN_SHA256:
				valid, err := verifySignedSignature(signatureBase, cryptKey, token)
				if err == nil && valid {
					s.VerificationData = SignaturePayload{}
					s.VerificationData["verdict"] = meta.Verdict
					s.VerificationData["result"] = result
					s.VerificationData["ipv"+strconv.Itoa(v)+"ip"] = ipAddress
					s.VerificationData[""] = verifyEmbeddedIpv6(s.Payload, result, cryptKey, userAgent, signRole)
					s.Result = result

					return nil
				}
			}

		}

	}

	return adscoreErrors.NewVerifyError("no verdict matched")
}

func verifyHashedSignature(signatureBase string, cryptKey []byte, token []byte) bool {
	xToken := createHmac(signatureBase, cryptKey)

	return bytes.Equal(xToken, token)
}

func createHmac(input string, cryptKey []byte) []byte {
	hmacHash := hmac.New(sha256.New, cryptKey)

	hmacHash.Write([]byte(input))

	return hmacHash.Sum(nil)
}

func verifySignedSignature(signatureBase string, cryptKey []byte, token []byte) (bool, error) {
	return adscoreCrypt.VerifyAsymmetric([]byte(signatureBase), token, cryptKey)
}

func getHashBase(result int, requestTime *int, signatureTime *int, ipAddress string, userAgent string) string {
	return fmt.Sprintf("%d\n%d\n%d\n%s\n%s",
		result,
		*requestTime,
		*signatureTime,
		ipAddress,
		userAgent,
	)
}

func readStructureField(signature []byte, fieldType string) (interface{}, []byte, error) {
	if SIMPLE_TYPES[fieldType] == nil {
		return nil, nil, errors.New("unsupported variable type " + fieldType)
	}

	var unpackFmtStr = SIMPLE_TYPES[fieldType].unpack
	var fieldSize = SIMPLE_TYPES[fieldType].size

	switch fieldType {
	case "uchar":
		fallthrough
	case "ushort":
		fallthrough
	case "ulong":
		var vData, err = utils.Unpack(unpackFmtStr, signature)
		if err != nil {
			return nil, nil, err
		}

		return vData["v"], signature[fieldSize:], nil

	case "string":
		var vData, err = utils.Unpack(unpackFmtStr, signature)
		if err != nil {
			return nil, nil, err
		}

		length := *vData["v"]

		if length&0x8000 > 0 {
			/* For future use */
			length = length & 0xff
		}

		if len(signature) < fieldSize+length {
			return nil, nil, adscoreErrors.NewParseError("premature end of signature")
		}

		var v2 = signature[fieldSize : fieldSize+length]

		if len(v2) != length {
			return nil, nil, errors.New("premature end of signature")
		}

		return v2, signature[fieldSize+length:], nil

	default:
		return nil, nil, errors.New("unsupported variable type " + fieldType)
	}

}

func verifyEmbeddedIpv6(data map[string]interface{}, result int, key []byte, userAgent string, signRole string) string {
	if signRole != "master" {
		return "" // Unable to verify signature integrity
	}

	// Fix #3: Безопасные type assertion
	ipV6Val, ok := data["ipV6"].(string)
	if !ok || ipV6Val == "" {
		return "" // No IPv6 supplied
	}

	tokenV6Val, ok := data[signRole+"TokenV6"].(string)
	if !ok || tokenV6Val == "" {
		return "" // No IPv6 tokens supplied
	}

	tokenVal, ok := data[signRole+"Token"].(string)
	if !ok {
		return "" // No token supplied
	}

	checksumVal, ok := data[signRole+"Checksum"].([]byte)
	if !ok {
		return "" // No checksum supplied
	}

	checksum := createHmac(tokenVal+tokenV6Val, key)
	if !bytes.Equal(checksum, checksumVal) {
		return "" // Integrity not preserved
	}

	ipAddress := net.ParseIP(ipV6Val)
	if ipAddress == nil || ipAddress.To16() == nil {
		return "" // Not valid IPv6 struct
	}

	signTypeVal, ok := data[signRole+"SignType"].(string)
	if !ok {
		return "" // No signType supplied
	}

	requestTimeVal, ok := data["requestTime"].(*int)
	if !ok {
		return "" // No requestTime supplied
	}
	signatureTimeVal, ok := data["signatureTime"].(*int)
	if !ok {
		return "" // No signatureTime supplied
	}

	signatureBase := getHashBase(result, requestTimeVal, signatureTimeVal, ipAddress.String(), userAgent)

	switch signTypeVal {
	case "sha256":
		xToken := createHmac(signatureBase, key)
		tokenV6Bytes, ok := data[signRole+"TokenV6"].([]byte)
		if ok && bytes.Equal(xToken, tokenV6Bytes) {
			return ipAddress.String()
		}
		// Customer verification currently unsupported
	}

	return ""
}
