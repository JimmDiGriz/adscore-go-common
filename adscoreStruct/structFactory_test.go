package adscoreStruct

import (
	"testing"
)

func TestDecodeStructFromPayload_JSON(t *testing.T) {
	// Payload: header 'J' + JSON данные
	payload := append([]byte{'J'}, []byte(`{"result":9,"ip":"1.2.3.4"}`)...)

	result, err := DecodeStructFromPayload(payload)
	if err != nil {
		t.Fatalf("DecodeStructFromPayload() error = %v", err)
	}

	if result["result"] != float64(9) {
		t.Errorf("result = %v, want 9", result["result"])
	}
	if result["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v, want 1.2.3.4", result["ip"])
	}
}

func TestDecodeStructFromPayload_RFC3986(t *testing.T) {
	// Payload: header 'H' + RFC3986 query string
	payload := append([]byte{'H'}, []byte(`result=9&ipv4.ip=1.2.3.4`)...)

	result, err := DecodeStructFromPayload(payload)
	if err != nil {
		t.Fatalf("DecodeStructFromPayload() error = %v", err)
	}

	// Fix #9: result теперь int
	if result["result"] != 9 {
		t.Errorf("result = %v, want 9", result["result"])
	}
	if result["ipv4.ip"] != "1.2.3.4" {
		t.Errorf("ipv4.ip = %v, want 1.2.3.4", result["ipv4.ip"])
	}
}

func TestDecodeStructFromPayload_Empty(t *testing.T) {
	// Пустой payload
	_, err := DecodeStructFromPayload([]byte{})
	if err == nil {
		t.Error("DecodeStructFromPayload() expected error for empty payload")
	}
}

func TestDecodeStructFromPayload_SingleByte(t *testing.T) {
	// Payload из 1 байта (меньше 2)
	_, err := DecodeStructFromPayload([]byte{'J'})
	if err == nil {
		t.Error("DecodeStructFromPayload() expected error for single byte payload")
	}
}

func TestDecodeStructFromPayload_UnsupportedType(t *testing.T) {
	// Неподдерживаемый тип структуры
	payload := append([]byte{'X'}, []byte(`data`)...)

	_, err := DecodeStructFromPayload(payload)
	if err == nil {
		t.Error("DecodeStructFromPayload() expected error for unsupported type")
	}
}

func TestDecodeStruct_JSON(t *testing.T) {
	data := []byte(`{"key":"value","num":123}`)

	result, err := DecodeStruct("json", data)
	if err != nil {
		t.Fatalf("DecodeStruct() error = %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
	if result["num"] != float64(123) {
		t.Errorf("num = %v, want 123", result["num"])
	}
}

func TestDecodeStruct_JSON_Uppercase(t *testing.T) {
	data := []byte(`{"test":true}`)

	result, err := DecodeStruct("Json", data)
	if err != nil {
		t.Fatalf("DecodeStruct() error = %v", err)
	}

	if result["test"] != true {
		t.Errorf("test = %v, want true", result["test"])
	}
}

func TestDecodeStruct_JSON_SingleChar(t *testing.T) {
	data := []byte(`{"a":1}`)

	result, err := DecodeStruct("J", data)
	if err != nil {
		t.Fatalf("DecodeStruct() error = %v", err)
	}

	if result["a"] != float64(1) {
		t.Errorf("a = %v, want 1", result["a"])
	}
}

func TestDecodeStruct_RFC3986(t *testing.T) {
	data := []byte(`key=value&foo=bar`)

	result, err := DecodeStruct("rfc3986", data)
	if err != nil {
		t.Fatalf("DecodeStruct() error = %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
	if result["foo"] != "bar" {
		t.Errorf("foo = %v, want bar", result["foo"])
	}
}

func TestDecodeStruct_RFC3986_Uppercase(t *testing.T) {
	data := []byte(`test=123`)

	result, err := DecodeStruct("Rfc3986", data)
	if err != nil {
		t.Fatalf("DecodeStruct() error = %v", err)
	}

	// Fix #9: test теперь int
	if result["test"] != 123 {
		t.Errorf("test = %v, want 123", result["test"])
	}
}

func TestDecodeStruct_RFC3986_SingleChar(t *testing.T) {
	data := []byte(`a=b`)

	result, err := DecodeStruct("H", data)
	if err != nil {
		t.Fatalf("DecodeStruct() error = %v", err)
	}

	if result["a"] != "b" {
		t.Errorf("a = %v, want b", result["a"])
	}
}

func TestDecodeStruct_UnsupportedType(t *testing.T) {
	_, err := DecodeStruct("xml", []byte(`<data/>`))
	if err == nil {
		t.Error("DecodeStruct() expected error for unsupported type")
	}
}

func TestDecodeStruct_EmptyData(t *testing.T) {
	// Пустые данные для JSON — ошибка
	_, err := DecodeStruct("json", []byte{})
	if err == nil {
		t.Error("DecodeStruct() expected error for empty JSON data")
	}
}
