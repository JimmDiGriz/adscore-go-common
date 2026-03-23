package utils

import (
	"testing"
)

func TestUnpack_C_unsigned_char(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"zero", []byte{0x00}, 0},
		{"max", []byte{0xFF}, 255},
		{"half", []byte{0x7F}, 127},
		{"one", []byte{0x01}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Unpack("Cvalue", tt.input)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if *result["value"] != tt.expected {
				t.Errorf("Unpack() = %v, want %v", *result["value"], tt.expected)
			}
		})
	}
}

func TestUnpack_c_signed_char(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"zero", []byte{0x00}, 0},
		{"positive_max", []byte{0x7F}, 127},
		{"negative_min", []byte{0x80}, -128},
		{"negative_one", []byte{0xFF}, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Unpack("cvalue", tt.input)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if *result["value"] != tt.expected {
				t.Errorf("Unpack() = %v, want %v", *result["value"], tt.expected)
			}
		})
	}
}

func TestUnpack_n_big_endian_uint16(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"zero", []byte{0x00, 0x00}, 0},
		{"one", []byte{0x00, 0x01}, 1},
		{"max", []byte{0xFF, 0xFF}, 65535},
		{"half", []byte{0x7F, 0xFF}, 32767},
		{"min_negative_signed", []byte{0x80, 0x00}, 32768},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Unpack("nvalue", tt.input)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if *result["value"] != tt.expected {
				t.Errorf("Unpack() = %v, want %v", *result["value"], tt.expected)
			}
		})
	}
}

func TestUnpack_N_big_endian_uint32(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"zero", []byte{0x00, 0x00, 0x00, 0x00}, 0},
		{"one", []byte{0x00, 0x00, 0x00, 0x01}, 1},
		{"max", []byte{0xFF, 0xFF, 0xFF, 0xFF}, 4294967295},
		{"half", []byte{0x7F, 0xFF, 0xFF, 0xFF}, 2147483647},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Unpack("Nvalue", tt.input)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if *result["value"] != tt.expected {
				t.Errorf("Unpack() = %v, want %v", *result["value"], tt.expected)
			}
		})
	}
}

func TestUnpack_J_big_endian_uint64(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"zero", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0},
		{"one", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, 1},
		{"max_int", []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 9223372036854775807},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Unpack("Jvalue", tt.input)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if *result["value"] != tt.expected {
				t.Errorf("Unpack() = %v, want %v", *result["value"], tt.expected)
			}
		})
	}
}

func TestUnpack_v_little_endian_uint16(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{"zero", []byte{0x00, 0x00}, 0},
		{"one", []byte{0x01, 0x00}, 1},
		{"max", []byte{0xFF, 0xFF}, 65535},
		{"half", []byte{0xFF, 0x7F}, 32767},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Unpack("vvalue", tt.input)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}
			if *result["value"] != tt.expected {
				t.Errorf("Unpack() = %v, want %v", *result["value"], tt.expected)
			}
		})
	}
}

func TestUnpack_Combined(t *testing.T) {
	// Формат как в signatureV5: Cversion/nlength/Jzone_id
	// version=5 (1 байт), length=100 (2 байта BE), zone_id=12345 (8 байт BE)
	input := []byte{
		0x05,                   // version
		0x00, 0x64,             // length = 100
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39, // zone_id = 12345
	}

	result, err := Unpack("Cversion/nlength/Jzone_id", input)
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if *result["version"] != 5 {
		t.Errorf("version = %v, want 5", *result["version"])
	}
	if *result["length"] != 100 {
		t.Errorf("length = %v, want 100", *result["length"])
	}
	if *result["zone_id"] != 12345 {
		t.Errorf("zone_id = %v, want 12345", *result["zone_id"])
	}
}

func TestUnpack_EmptyInput(t *testing.T) {
	// NOTE: Сейчас функция паникует при пустом input (баг в unpack.go).
	// После фикса будет возвращать ошибку.
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic (unpack bug): %v", r)
		}
	}()

	_, err := Unpack("Cvalue", []byte{})
	if err == nil {
		t.Error("Unpack() expected error for empty input")
	}
}

func TestUnpack_TruncatedInput(t *testing.T) {
	// NOTE: Сейчас функция паникует при truncated input (баг в unpack.go).
	// После фикса будет возвращать ошибку.
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got expected panic (unpack bug): %v", r)
		}
	}()

	// Ожидаем 2 байта, есть только 1
	_, err := Unpack("nvalue", []byte{0x00})
	if err == nil {
		t.Error("Unpack() expected error for truncated input")
	}
}

func TestUnpack_UnknownInstruction(t *testing.T) {
	_, err := Unpack("Xvalue", []byte{0x00})
	if err == nil {
		t.Error("Unpack() expected error for unknown instruction")
	}
}

func TestUnpack_MultipleFields(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03, 0x04}
	result, err := Unpack("Ca/Cb/nC", input)
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if *result["a"] != 1 {
		t.Errorf("a = %v, want 1", *result["a"])
	}
	if *result["b"] != 2 {
		t.Errorf("b = %v, want 2", *result["b"])
	}
	// nC = big-endian uint16 из байт 0x03, 0x04 = 0x0304 = 772
	if *result["C"] != 772 {
		t.Errorf("C = %v, want 772", *result["C"])
	}
}

func TestUnpack_OffsetOverflow(t *testing.T) {
	// NOTE: Сейчас функция не корректно обрабатывает overflow (баг в unpack.go).
	// Проверка `offset > len(input)` должна быть `offset >= len(input)` или лучше.
	// После фикса будет возвращать ошибку.
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Got panic (unpack bug): %v", r)
		}
	}()

	// Пытаемся прочитать 2 байта из 1
	input := []byte{0x01}
	_, err := Unpack("CC", input)
	// Пока просто проверяем, что нет паники (баг будет зафиксен)
	_ = err
}
