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
	// Fix #9: Теперь RFC3986 парсер возвращает числа как int
	payload := []byte(`result=9&count=123`)

	result, err := decodeRFC3986Struct(payload)
	if err != nil {
		t.Fatalf("decodeRFC3986Struct() error = %v", err)
	}

	// Теперь ожидаем int
	if result["result"] != 9 {
		t.Errorf("result = %v, want 9", result["result"])
	}
	if result["count"] != 123 {
		t.Errorf("count = %v, want 123", result["count"])
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

	// Fix #9: Числа парсятся как int
	if result["a"] != 1 {
		t.Errorf("a = %v, want 1", result["a"])
	}
	if result["b"] != 2 {
		t.Errorf("b = %v, want 2", result["b"])
	}
	if result["c"] != 3 {
		t.Errorf("c = %v, want 3", result["c"])
	}
	if result["d"] != 4 {
		t.Errorf("d = %v, want 4", result["d"])
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
