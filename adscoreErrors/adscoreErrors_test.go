package adscoreErrors

import (
	"testing"
)

func TestVersionError(t *testing.T) {
	msg := "invalid version"
	err := NewVersionError(msg)

	if err.Error() != msg {
		t.Errorf("VersionError.Error() = %v, want %v", err.Error(), msg)
	}
}

func TestParseError(t *testing.T) {
	msg := "premature end of signature"
	err := NewParseError(msg)

	if err.Error() != msg {
		t.Errorf("ParseError.Error() = %v, want %v", err.Error(), msg)
	}
}

func TestVerifyError(t *testing.T) {
	msg := "signature IP mismatch"
	err := NewVerifyError(msg)

	if err.Error() != msg {
		t.Errorf("VerifyError.Error() = %v, want %v", err.Error(), msg)
	}
}

func TestVersionError_NilMessage(t *testing.T) {
	err := NewVersionError("")

	if err.Error() != "" {
		t.Errorf("VersionError with empty message = %v, want empty string", err.Error())
	}
}

func TestParseError_NilMessage(t *testing.T) {
	err := NewParseError("")

	if err.Error() != "" {
		t.Errorf("ParseError with empty message = %v, want empty string", err.Error())
	}
}

func TestVerifyError_NilMessage(t *testing.T) {
	err := NewVerifyError("")

	if err.Error() != "" {
		t.Errorf("VerifyError with empty message = %v, want empty string", err.Error())
	}
}

func TestErrorsAreDifferentTypes(t *testing.T) {
	versionErr := NewVersionError("version")
	parseErr := NewParseError("parse")
	verifyErr := NewVerifyError("verify")

	// Проверяем, что ошибки разных типов не равны
	if versionErr.Error() == parseErr.Error() {
		t.Error("VersionError and ParseError should have different messages")
	}
	if versionErr.Error() == verifyErr.Error() {
		t.Error("VersionError and VerifyError should have different messages")
	}
	if parseErr.Error() == verifyErr.Error() {
		t.Error("ParseError and VerifyError should have different messages")
	}
}
