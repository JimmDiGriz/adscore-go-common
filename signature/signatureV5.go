package adscoreSignature

import (
	"errors"
	"net"
	"strconv"

	adscoreErrors "github.com/JimmDiGriz/adscore-go-common/adscoreErrors"
	adscoreStruct "github.com/JimmDiGriz/adscore-go-common/adscoreStruct"
	crypt "github.com/JimmDiGriz/adscore-go-common/crypt"
	formatter "github.com/JimmDiGriz/adscore-go-common/formatter"
	utils "github.com/JimmDiGriz/adscore-go-common/utils"
)

const SUPPORTED_VERSION_V5 = 5
const HEADER_LENGTH = 11

type SignaturePayload map[string]interface{}

type Signature5 struct {
	VERSION int
	ZoneId  int64
	Payload SignaturePayload
	Result  int
}

func CreateSignatureV5FromRequest(signature string, ipAddresses []string, userAgent string, cryptKey []byte) (*Signature5, error) {
	obj := &Signature5{
		VERSION: SUPPORTED_VERSION_V5,
	}

	if len(signature) == 0 {
		return nil, adscoreErrors.NewParseError("premature end of signature")
	}

	err := obj.Parse(signature, cryptKey, "BASE64_VARIANT_URLSAFE_NO_PADDING")

	if err != nil {
		return nil, err
	}

	err = obj.Verify(ipAddresses, userAgent)

	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *Signature5) Verify(ipAddresses []string, userAgent string) error {
	// Fix #1: Проверяем, что Payload инициализирован
	if s.Payload == nil {
		return adscoreErrors.NewVerifyError("payload not initialized")
	}

	var matchingIp net.IP = nil

	for _, ipAddress := range ipAddresses {
		providedIpAddress := net.ParseIP(ipAddress)

		// Проверяем ipv4.ip с type assertion
		if ipV4Field, ok := s.Payload["ipv4.ip"].(string); ok {
			if net.IP.Equal(providedIpAddress, net.ParseIP(ipV4Field)) {
				matchingIp = providedIpAddress
				break
			}
		}

		// Проверяем ipv6.ip с type assertion
		if ipV6Field, ok := s.Payload["ipv6.ip"].(string); ok {
			if net.IP.Equal(providedIpAddress, net.ParseIP(ipV6Field)) {
				matchingIp = providedIpAddress
				break
			}
		}
	}

	if matchingIp == nil {
		return adscoreErrors.NewVerifyError("signature IP mismatch")
	}

	// Проверяем b.ua с type assertion
	signatureUserAgent, ok := s.Payload["b.ua"].(string)
	if !ok {
		return adscoreErrors.NewVerifyError("signature contains no user agent")
	}

	if signatureUserAgent == "" {
		return adscoreErrors.NewVerifyError("signature contains no user agent")
	}

	if signatureUserAgent != userAgent {
		return adscoreErrors.NewVerifyError("signature user agent mismatch")
	}

	// Fix #8: Проверяем result на nil перед type assertion
	resultField := s.Payload["result"]
	if resultField == nil {
		return adscoreErrors.NewParseError("missing result in payload")
	}

	switch v := resultField.(type) {
	case string:
		result, err := strconv.ParseInt(v, 10, 8)
		if err != nil {
			return err
		}
		s.Result = int(result)
	case float64:
		s.Result = int(v)
	default:
		return errors.New("invalid result type, expected string or float64")
	}

	return nil
}

func (s *Signature5) Parse(signature string, cryptKey []byte, format string) error {
	encryptedPayload, payloadDecodeError := formatter.Parse(signature, format)
	if payloadDecodeError != nil {
		return payloadDecodeError
	}

	var data, payloadUnpackError = utils.Unpack("Cversion/nlength/Jzone_id", encryptedPayload)
	if payloadUnpackError != nil {
		return payloadUnpackError
	}

	var version = *data["version"]
	var length = *data["length"]

	if version != SUPPORTED_VERSION_V5 {
		return adscoreErrors.NewVersionError("invalid signature version")
	}

	if len(encryptedPayload) < length+HEADER_LENGTH {
		return adscoreErrors.NewParseError("premature end of signature")
	}

	encryptedPayload = encryptedPayload[HEADER_LENGTH : length+HEADER_LENGTH]

	if len(encryptedPayload) < length {
		return adscoreErrors.NewParseError("truncated signature payload")
	}

	// Fix #7: Сначала расшифровываем, потом записываем данные
	result, err := decryptPayload(encryptedPayload, cryptKey)
	if err != nil {
		return err
	}

	s.ZoneId = int64(*data["zone_id"])
	s.Payload = result

	return nil
}

func GetZoneId(signature string, format string) (int64, error) {
	encryptedPayload, payloadDecodeError := formatter.Parse(signature, format)

	if payloadDecodeError != nil {
		return -1, payloadDecodeError
	}

	var data, payloadUnpackError = utils.Unpack("Cversion/nlength/Jzone_id", encryptedPayload)

	if payloadUnpackError != nil {
		return -1, payloadUnpackError
	}

	var version = *data["version"]

	if version != SUPPORTED_VERSION_V5 {
		return -1, adscoreErrors.NewVersionError("invalid signature version")
	}

	zoneId := int64(*data["zone_id"])

	return zoneId, nil
}

func decryptPayload(encryptedPayload []byte, cryptKey []byte) (map[string]interface{}, error) {
	decryptedPayload, err := crypt.DecryptSymmetricOpenSsl(encryptedPayload, cryptKey)

	if err != nil {
		return nil, err
	}

	return adscoreStruct.DecodeStructFromPayload(decryptedPayload)
}
