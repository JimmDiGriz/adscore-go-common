package adscoreStruct

import (
	"testing"
)

func Test_decodeJson_WithEOT(t *testing.T) {
	// JSON с EOT (0x04) в конце
	payload := []byte(`{"result":9}`)
	payload = append(payload, 0x04)

	result, err := decodeJson(payload)
	if err != nil {
		t.Fatalf("decodeJson() error = %v", err)
	}

	if result["result"] != float64(9) {
		t.Errorf("result = %v, want 9", result["result"])
	}
}

func Test_decodeJson_WithoutEOT(t *testing.T) {
	payload := []byte(`{"key":"value"}`)

	result, err := decodeJson(payload)
	if err != nil {
		t.Fatalf("decodeJson() error = %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
}

func Test_decodeJson_MultipleEOT(t *testing.T) {
	// JSON с множественными EOT
	payload := []byte(`{"test":true}`)
	payload = append(payload, 0x04, 0x04, 0x04)

	result, err := decodeJson(payload)
	if err != nil {
		t.Fatalf("decodeJson() error = %v", err)
	}

	if result["test"] != true {
		t.Errorf("test = %v, want true", result["test"])
	}
}

func Test_decodeJson_EOTInMiddle(t *testing.T) {
	// EOT в середине удаляется trimPayload, что ломает JSON
	// Это ожидаемое поведение — trimPayload удаляет все 0x04
	payload := []byte{'{', '"', 't', 'e', 0x04, 's', 't', '"', ':', 't', 'r', 'u', 'e', '}'}

	result, err := decodeJson(payload)
	if err != nil {
		t.Fatalf("decodeJson() error = %v", err)
	}

	// После trimPayload ключ становится "test" (без EOT)
	if result["test"] != true {
		t.Errorf("test = %v, want true", result["test"])
	}
}

func Test_decodeJson_EmptyPayload(t *testing.T) {
	_, err := decodeJson([]byte{})
	if err == nil {
		t.Error("decodeJson() expected error for empty payload")
	}
}

func Test_decodeJson_InvalidJSON(t *testing.T) {
	payload := []byte(`{invalid json}`)

	_, err := decodeJson(payload)
	if err == nil {
		t.Error("decodeJson() expected error for invalid JSON")
	}
}

func Test_decodeJson_ComplexObject(t *testing.T) {
	payload := []byte(`{"nested":{"a":1},"array":[1,2,3],"bool":false}`)

	result, err := decodeJson(payload)
	if err != nil {
		t.Fatalf("decodeJson() error = %v", err)
	}

	nested, ok := result["nested"].(map[string]interface{})
	if !ok {
		t.Fatal("nested is not a map")
	}
	if nested["a"] != float64(1) {
		t.Errorf("nested.a = %v, want 1", nested["a"])
	}

	array, ok := result["array"].([]interface{})
	if !ok {
		t.Fatal("array is not a slice")
	}
	if len(array) != 3 {
		t.Errorf("array length = %v, want 3", len(array))
	}

	if result["bool"] != false {
		t.Errorf("bool = %v, want false", result["bool"])
	}
}

func Test_trimPayload_NoEOT(t *testing.T) {
	input := []byte("hello world")
	result := trimPayload(input)

	if string(result) != "hello world" {
		t.Errorf("trimPayload() = %v, want hello world", string(result))
	}
}

func Test_trimPayload_SingleEOT(t *testing.T) {
	input := []byte("hello\x04")
	result := trimPayload(input)

	if string(result) != "hello" {
		t.Errorf("trimPayload() = %v, want hello", string(result))
	}
}

func Test_trimPayload_MultipleEOT(t *testing.T) {
	input := []byte("hello\x04\x04\x04")
	result := trimPayload(input)

	if string(result) != "hello" {
		t.Errorf("trimPayload() = %v, want hello", string(result))
	}
}

func Test_trimPayload_EOTOnly(t *testing.T) {
	input := []byte{0x04, 0x04, 0x04}
	result := trimPayload(input)

	if len(result) != 0 {
		t.Errorf("trimPayload() expected empty result, got %v", string(result))
	}
}

func Test_trimPayload_Empty(t *testing.T) {
	input := []byte{}
	result := trimPayload(input)

	if len(result) != 0 {
		t.Errorf("trimPayload() expected empty result, got %v", string(result))
	}
}
