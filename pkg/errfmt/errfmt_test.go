package errfmt

import (
	"errors"
	"fmt"
	"testing"

	"gotest.tools/assert"
)

func TestErrorf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format string
		args   []interface{}
		want   error
	}{
		{
			name:   "empty format string",
			format: "",
			args:   []interface{}{},
			want:   nil,
		},
		{
			name:   "non-empty format string",
			format: "an error occurred",
			args:   []interface{}{},
			want:   fmt.Errorf("errfmt.TestErrorf.func1: an error occurred"),
		},
		{
			name:   "format string with arguments",
			format: "an error occurred, %d",
			args:   []interface{}{42},
			want:   fmt.Errorf("errfmt.TestErrorf.func1: an error occurred, 42"),
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Errorf(tt.format, tt.args...)
			if tt.want == nil {
				assert.Equal(t, tt.want, got)
				return
			}
			assert.Equal(t, tt.want.Error(), got.Error(), "got: %v, want: %v", got.Error(), tt.want.Error())
		})
	}
}

func TestWrapError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "nil error",
			err:  nil,
			want: nil,
		},
		{
			name: "non-nil error",
			err:  errors.New("an error occurred"),
			want: fmt.Errorf("errfmt.TestWrapError.func1: an error occurred"),
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := WrapError(tt.err)
			if tt.want == nil {
				assert.Equal(t, tt.want, got)
				return
			}
			assert.Equal(t, tt.want.Error(), got.Error(), "got: %v, want: %v", got.Error(), tt.want.Error())
		})
	}
}
