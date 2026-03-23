package adscoreStruct

import (
	"encoding/json"
)

func decodeJson(payload []byte) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	err := json.Unmarshal(trimPayload(payload), &data)

	return data, err
}

// Fix #10: Оптимизированная версия trimPayload
// Выделяем память сразу, чтобы избежать реаллокаций
func trimPayload(payload []byte) []byte {
	result := make([]byte, 0, len(payload))
	for _, v := range payload {
		if v != 0x4 {
			result = append(result, v)
		}
	}
	return result
}
