package adscoreStruct

import (
	"strconv"
	"net/url"
)

func decodeRFC3986Struct(payload []byte) (map[string]interface{}, error) {
	queryValues, err := url.ParseQuery(string(payload))

	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{}

	for key, value := range queryValues {
		// Парсим числовые значения в float64 для совместимости с JSON парсером
		if len(value) == 1 {
			val := value[0]
			// Пробуем распарсить как int, конвертируем в float64
			if num, err := strconv.Atoi(val); err == nil {
				result[key] = float64(num)
			} else {
				result[key] = val
			}
		} else {
			result[key] = value
		}
	}

	return result, nil
}
