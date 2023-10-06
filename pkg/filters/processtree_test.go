package filters

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessTreeFilterParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inputs []string
		err    bool
		equal  map[uint32]struct{}
		notEq  map[uint32]struct{}
	}{
		{
			name: "equality",
			inputs: []string{
				"=123,456",
			},
			err: false,
			equal: map[uint32]struct{}{
				123: {},
				456: {},
			},
			notEq: map[uint32]struct{}{},
		},
		{
			name: "inequality",
			inputs: []string{
				"!=123,456",
			},
			err:   false,
			equal: map[uint32]struct{}{},
			notEq: map[uint32]struct{}{
				123: {},
				456: {},
			},
		},
		{
			name: "mixed",
			inputs: []string{
				"!=123,456",
				"=789,101112",
			},
			err: false,
			equal: map[uint32]struct{}{
				789:    {},
				101112: {},
			},
			notEq: map[uint32]struct{}{
				123: {},
				456: {},
			},
		},
		{
			name: "invalid input",
			inputs: []string{
				"123,456",
			},
			err: true,
		},
		{
			name: "invalid input",
			inputs: []string{
				"=",
			},
			err: true,
		},
		{
			name: "invalid input",
			inputs: []string{
				"!=",
			},
			err: true,
		},
		{
			name: "invalid input",
			inputs: []string{
				"=abcd",
			},
			err: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var err error
			filter := NewProcessTreeFilter()
			for _, expr := range test.inputs {
				err = filter.Parse(expr)
				if (err != nil) != test.err {
					t.Errorf("expected error status %v, got %v, input: %s", test.err, (err != nil), test.inputs)
				}
			}

			if err == nil {
				if !reflect.DeepEqual(filter.equal, test.equal) || !reflect.DeepEqual(filter.notEqual, test.notEq) {
					t.Errorf("unexpected parsed values for input %s", test.inputs)
				}
			}
		})
	}
}

func TestProcessTreeFilterFilterOut(t *testing.T) {
	t.Parallel()

	ptf1 := NewProcessTreeFilter()
	ptf1.Parse("=0")
	ptf1.Parse("=1")
	ptf1.Parse("=2")
	assert.False(t, ptf1.FilterOut())

	ptf2 := NewProcessTreeFilter()
	ptf2.Parse("=0")
	ptf2.Parse("!=1")
	ptf2.Parse("=2")
	assert.True(t, ptf2.FilterOut())

	ptf3 := NewProcessTreeFilter()
	ptf3.Parse("!=0")
	ptf3.Parse("=1")
	ptf3.Parse("!=2")
	assert.True(t, ptf3.FilterOut())

	ptf4 := NewProcessTreeFilter()
	ptf4.Parse("!=0")
	ptf4.Parse("!=1")
	ptf4.Parse("!=2")
	assert.True(t, ptf4.FilterOut())
}

func TestProcessTreeFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewProcessTreeFilter()
	err := filter.Parse("!=0")
	require.NoError(t, err)
	err = filter.Parse("!=1")
	require.NoError(t, err)

	copy := filter.Clone()

	if !reflect.DeepEqual(copy, filter) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	err = filter.Parse("=2")
	require.NoError(t, err)
	if reflect.DeepEqual(copy, filter) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
