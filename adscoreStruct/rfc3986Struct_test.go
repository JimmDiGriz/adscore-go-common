package adscoreStruct

import (
	"testing"
)

func Test_decodeRFC3986Struct_Simple(t *testing.T) {
	payload := []byte(`key=value&foo=bar`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
	if result["foo"] != "bar" {
		t.Errorf("foo = %v, want bar", result["foo"])
	}
}

func Test_decodeRFC3986Struct_NumericValues(t *testing.T) {
	// Fix #9: Парсим числа в float64 для совместимости с JSON парсером
	payload := []byte(`result=9&count=123`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	// Ожидаем float64 (как JSON парсер)
	if result["result"] != float64(9) {
		t.Errorf("result = %v (%T), want 9 (float64)", result["result"], result["result"])
	}
	if result["count"] != float64(123) {
		t.Errorf("count = %v (%T), want 123 (float64)", result["count"], result["count"])
	}
}

func Test_decodeRFC3986Struct_ArrayValues(t *testing.T) {
	payload := []byte(`tags=a&tags=b&tags=c`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	tags, ok := result["tags"].([]string)
	if !ok {
		t.Fatalf("tags is not a []string, got %T", result["tags"])
	}

	if len(tags) != 3 {
		t.Errorf("tags length = %v, want 3", len(tags))
	}
}

func Test_decodeRFC3986Struct_URLEncoded(t *testing.T) {
	payload := []byte(`name=hello%20world&url=https%3A%2F%2Fexample.com`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	if result["name"] != "hello world" {
		t.Errorf("name = %v, want hello world", result["name"])
	}
	if result["url"] != "https://example.com" {
		t.Errorf("url = %v, want https://example.com", result["url"])
	}
}

func Test_decodeRFC3986Struct_EmptyPayload(t *testing.T) {
	result, err := decodeRFC3986Struct([]byte{})
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("decodeRFC3986Struct() expected empty result, got %v", result)
	}
}

func Test_decodeRFC3986Struct_SinglePair(t *testing.T) {
	payload := []byte(`single=value`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	if result["single"] != "value" {
		t.Errorf("single = %v, want value", result["single"])
	}
}

func Test_decodeRFC3986Struct_EmptyValue(t *testing.T) {
	payload := []byte(`key=`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	if result["key"] != "" {
		t.Errorf("key = %v, want empty string", result["key"])
	}
}

func Test_decodeRFC3986Struct_NoValue(t *testing.T) {
	// Ключ без значения (без '=')
	payload := []byte(`keyonly`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	// url.ParseQuery возвращает пустую строку для ключа без значения
	if result["keyonly"] != "" {
		t.Errorf("keyonly = %v, want empty string", result["keyonly"])
	}
}

func Test_decodeRFC3986Struct_MultiplePairs(t *testing.T) {
	payload := []byte(`a=1&b=2&c=3&d=4`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	// Ожидаем float64 (как JSON парсер)
	if result["a"] != float64(1) {
		t.Errorf("a = %v (%T), want 1 (float64)", result["a"], result["a"])
	}
	if result["b"] != float64(2) {
		t.Errorf("b = %v (%T), want 2 (float64)", result["b"], result["b"])
	}
	if result["c"] != float64(3) {
		t.Errorf("c = %v (%T), want 3 (float64)", result["c"], result["c"])
	}
	if result["d"] != float64(4) {
		t.Errorf("d = %v (%T), want 4 (float64)", result["d"], result["d"])
	}
}

func Test_decodeRFC3986Struct_SpecialCharacters(t *testing.T) {
	payload := []byte(`email=test%40example.com&price=%24100`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	if result["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", result["email"])
	}
	if result["price"] != "$100" {
		t.Errorf("price = %v, want $100", result["price"])
	}
}
