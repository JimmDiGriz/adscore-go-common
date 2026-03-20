package judge

import (
	"testing"
)

func TestJudge_MapKeys(t *testing.T) {
	expectedKeys := []int{0, 3, 6, 9}

	for _, key := range expectedKeys {
		if _, ok := Judge[key]; !ok {
			t.Errorf("Judge missing key %d", key)
		}
	}
}

func TestJudge_MapValues(t *testing.T) {
	expected := map[int]string{
		0: "ok",
		3: "junk",
		6: "proxy",
		9: "bot",
	}

	for key, expectedValue := range expected {
		if value, ok := Judge[key]; !ok {
			t.Errorf("Judge missing key %d", key)
		} else if value != expectedValue {
			t.Errorf("Judge[%d] = %v, want %v", key, value, expectedValue)
		}
	}
}

func TestRESULTS_MapKeys(t *testing.T) {
	expectedKeys := []int{0, 3, 6, 9}

	for _, key := range expectedKeys {
		if _, ok := RESULTS[key]; !ok {
			t.Errorf("RESULTS missing key %d", key)
		}
	}
}

func TestRESULTS_MapValues(t *testing.T) {
	expected := map[int]struct {
		Verdict string
		Name    string
	}{
		0: {Verdict: "ok", Name: "Clean"},
		3: {Verdict: "junk", Name: "Potentially unwanted"},
		6: {Verdict: "proxy", Name: "Proxy"},
		9: {Verdict: "bot", Name: "Bot"},
	}

	for key, expectedValue := range expected {
		if value, ok := RESULTS[key]; !ok {
			t.Errorf("RESULTS missing key %d", key)
		} else {
			if value.Verdict != expectedValue.Verdict {
				t.Errorf("RESULTS[%d].Verdict = %v, want %v", key, value.Verdict, expectedValue.Verdict)
			}
			if value.Name != expectedValue.Name {
				t.Errorf("RESULTS[%d].Name = %v, want %v", key, value.Name, expectedValue.Name)
			}
		}
	}
}

func TestRESULTS_Consistency(t *testing.T) {
	// Проверяем, что ключи Judge и RESULTS совпадают
	for key := range Judge {
		if _, ok := RESULTS[key]; !ok {
			t.Errorf("Judge has key %d but RESULTS does not", key)
		}
	}

	for key := range RESULTS {
		if _, ok := Judge[key]; !ok {
			t.Errorf("RESULTS has key %d but Judge does not", key)
		}
	}
}
