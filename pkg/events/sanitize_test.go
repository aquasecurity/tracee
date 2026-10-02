package events

import (
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
)

func TestSanitizeStringForProtobuf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "ascii unchanged", input: "/usr/bin/bash", want: "/usr/bin/bash"},
		{name: "multibyte unchanged", input: "café ✓ 日本語", want: "café ✓ 日本語"},
		{name: "encoded U+FFFD unchanged", input: "a�b", want: "a�b"},
		{name: "lone continuation byte", input: "abc\x80def", want: "abc�def"},
		{name: "run of invalid bytes collapses to one marker", input: "abc\x80\xff\xfedef", want: "abc�def"},
		{name: "separate runs get separate markers", input: "\xffa\xffb\xff", want: "�a�b�"},
		{name: "truncated multibyte sequence at end", input: "caf\xc3", want: "caf�"},
		{name: "utf-16 surrogate encoding is invalid", input: "x\xed\xa0\x80y", want: "x�y"},
		{name: "overlong encoding is invalid", input: "x\xc0\xafy", want: "x�y"},
		{name: "encoded U+FFFD kept next to an invalid byte", input: "a�b\xff", want: "a�b�"},
		{name: "only invalid bytes", input: "\xff\xfe", want: "�"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := SanitizeStringForProtobuf(tt.input)
			assert.Equal(t, tt.want, got)
			assert.True(t, utf8.ValidString(got))

			// The reason the helper exists: the result must be accepted by
			// proto.Marshal, which rejects invalid UTF-8 in proto3 strings.
			_, err := proto.Marshal(&pb.EventValue{Name: got, Value: &pb.EventValue_Str{Str: got}})
			require.NoError(t, err)
		})
	}
}

// Every string field of every streamed event goes through the sanitizer, so
// the valid-input fast path must not allocate. Not parallel: AllocsPerRun reads
// process-wide allocation counters.
func TestSanitizeStringForProtobuf_ValidInputDoesNotAllocate(t *testing.T) {
	input := "/var/run/docker.sock"
	allocs := testing.AllocsPerRun(100, func() {
		_ = SanitizeStringForProtobuf(input)
	})
	assert.Zero(t, allocs)
}

func TestSanitizeStringArrayForProtobuf(t *testing.T) {
	t.Parallel()

	got := sanitizeStringArrayForProtobuf([]string{"ok", "bad\xff", "�", ""})
	assert.Equal(t, []string{"ok", "bad�", "�", ""}, got)
}
