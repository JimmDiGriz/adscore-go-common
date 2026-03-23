package adscoreStruct

import (
	"bytes"
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

// Test_trimPayload_Compatibility проверяет что оптимизированная версия
// возвращает тот же результат что и старая (наивная) реализация
func Test_trimPayload_Compatibility(t *testing.T) {
	// Старая (наивная) реализация для сравнения
	oldTrimPayload := func(payload []byte) []byte {
		result := []byte{}
		for _, v := range payload {
			if v != 0x4 {
				result = append(result, v)
			}
		}
		return result
	}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"no_eot", []byte("hello world")},
		{"single_eot_end", []byte("hello\x04")},
		{"multiple_eot_end", []byte("hello\x04\x04\x04")},
		{"eot_only", []byte{0x04, 0x04, 0x04}},
		{"eot_middle", []byte{'h', 'e', 0x04, 'l', 'l', 'o'}},
		{"eot_everywhere", []byte{0x04, 'a', 0x04, 'b', 0x04, 'c', 0x04}},
		{"large_payload", func() []byte {
			data := make([]byte, 10000)
			for i := range data {
				if i%10 == 0 {
					data[i] = 0x04
				} else {
					data[i] = byte('a' + (i % 26))
				}
			}
			return data
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldResult := oldTrimPayload(tt.input)
			newResult := trimPayload(tt.input)

			if !bytes.Equal(oldResult, newResult) {
				t.Errorf("trimPayload() mismatch!\nold: %v\nnew: %v", oldResult, newResult)
			}
		})
	}
}

// Benchmark_trimPayload_Old бенчмарк старой (наивной) реализации
func Benchmark_trimPayload_Old(b *testing.B) {
	oldTrimPayload := func(payload []byte) []byte {
		result := []byte{}
		for _, v := range payload {
			if v != 0x4 {
				result = append(result, v)
			}
		}
		return result
	}

	input := make([]byte, 1000)
	for i := range input {
		if i%10 == 0 {
			input[i] = 0x04
		} else {
			input[i] = byte('a' + (i % 26))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = oldTrimPayload(input)
	}
}

// Benchmark_trimPayload_New бенчмарк новой (оптимизированной) реализации
func Benchmark_trimPayload_New(b *testing.B) {
	input := make([]byte, 1000)
	for i := range input {
		if i%10 == 0 {
			input[i] = 0x04
		} else {
			input[i] = byte('a' + (i % 26))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = trimPayload(input)
	}
}
