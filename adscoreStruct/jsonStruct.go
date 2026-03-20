package adscoreStruct

import (
	"bytes"
	"encoding/json"
)

func decodeJson(payload []byte) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	err := json.Unmarshal(trimPayload(payload), &data)

	return data, err
}

// Fix #10: Оптимизированная версия trimPayload с bytes.Buffer
func trimPayload(payload []byte) []byte {
	var builder bytes.Buffer
	builder.Grow(len(payload))

	for _, v := range payload {
		// trim end of transmission ASCII char
		if v != 0x4 {
			builder.WriteByte(v)
		}
	}

	return builder.Bytes()
}
