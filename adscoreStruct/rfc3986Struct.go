package adscoreStruct

import (
	"net/url"
	"strconv"
)

func decodeRFC3986Struct(payload []byte) (map[string]interface{}, error) {
	queryValues, err := url.ParseQuery(string(payload))

	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{}

	for key, value := range queryValues {
		// Fix #9: Парсим числовые значения
		if len(value) == 1 {
			val := value[0]
			// Пробуем распарсить как int
			if num, err := strconv.Atoi(val); err == nil {
				result[key] = num
			} else {
				result[key] = val
			}
		} else {
			result[key] = value
		}
	}

	return result, nil
}
