package elf

import (
	"testing"
)

func TestParseGoVersion(t *testing.T) {
	tests := []struct {
		input       string
		expectError bool
		major       int
		minor       int
		patch       int
	}{
		{"go1.19.5", false, 1, 19, 5},
		{"go1.20", false, 1, 20, 0},
		{"go2.0.1", false, 2, 0, 1},
		{"go1.19.0", false, 1, 19, 0},
		{"invalid", true, 0, 0, 0},
		{"go", true, 0, 0, 0},
		{"go1", true, 0, 0, 0},
		{"go1.x", true, 0, 0, 0},
		{"", true, 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseGoVersion(tt.input)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result.Major != tt.major || result.Minor != tt.minor || result.Patch != tt.patch {
				t.Errorf("Got %d.%d.%d, want %d.%d.%d",
					result.Major, result.Minor, result.Patch,
					tt.major, tt.minor, tt.patch)
			}
		})
	}
}

func TestErrNotGoBinary(t *testing.T) {
	if ErrNotGoBinary == nil {
		t.Error("ErrNotGoBinary should not be nil")
	}

	expected := "not a go binary"
	if ErrNotGoBinary.Error() != expected {
		t.Errorf("Expected %q, got %q", expected, ErrNotGoBinary.Error())
	}
}
