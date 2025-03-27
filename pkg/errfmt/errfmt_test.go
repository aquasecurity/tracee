package errfmt

import (
	"errors"
<<<<<<< Updated upstream
=======
	"strings"
>>>>>>> Stashed changes
	"testing"
)

func TestErrorf(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		args     []interface{}
		wantErr  bool
		contains string
	}{
		{
			name:     "simple error message",
			format:   "test error",
			args:     nil,
			wantErr:  true,
			contains: "TestErrorf: test error",
		},
		{
<<<<<<< Updated upstream
			name:   "non-empty format string",
			format: "an error occurred",
			args:   []interface{}{},
			want:   errors.New("errfmt.TestErrorf.func1: an error occurred"),
		},
		{
			name:   "format string with arguments",
			format: "an error occurred, %d",
			args:   []interface{}{42},
			want:   errors.New("errfmt.TestErrorf.func1: an error occurred, 42"),
=======
			name:     "formatted error message",
			format:   "error %d: %s",
			args:     []interface{}{1, "test"},
			wantErr:  true,
			contains: "TestErrorf: error 1: test",
		},
		{
			name:    "empty message",
			format:  "",
			args:    nil,
			wantErr: false,
>>>>>>> Stashed changes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Errorf(tt.format, tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Errorf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("Errorf() error = %v, should contain %v", err, tt.contains)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantErr  bool
		contains string
	}{
		{
			name:     "wrap existing error",
			err:      errors.New("original error"),
			wantErr:  true,
			contains: "TestWrapError: original error",
		},
		{
<<<<<<< Updated upstream
			name: "non-nil error",
			err:  errors.New("an error occurred"),
			want: errors.New("errfmt.TestWrapError.func1: an error occurred"),
=======
			name:    "wrap nil error",
			err:     nil,
			wantErr: false,
>>>>>>> Stashed changes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WrapError(tt.err)
			if (err != nil) != tt.wantErr {
				t.Errorf("WrapError() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("WrapError() error = %v, should contain %v", err, tt.contains)
			}
		})
	}
}

func Test_funcName(t *testing.T) {
	name := funcName(0)
	expected := "Test_funcName"
	if name != expected {
		t.Errorf("funcName(0) = %v, want %v", name, expected)
	}

	// Test through a wrapper function to verify skip behavior
	wrapper := func() string {
		return funcName(1)
	}
	name = wrapper()
	if name != "Test_funcName" {
		t.Errorf("funcName(1) through wrapper = %v, want Test_funcName", name)
	}
}

func Test_prefixFunc(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		skip     int
		contains string
	}{
		{
			name:     "simple message",
			msg:      "test message",
			skip:     0,
			contains: "Test_prefixFunc: test message",
		},
		{
			name:     "empty message",
			msg:      "",
			skip:     0,
			contains: "Test_prefixFunc: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := prefixFunc(tt.msg, tt.skip)
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("prefixFunc() error = %v, should contain %v", err, tt.contains)
			}
		})
	}
}
