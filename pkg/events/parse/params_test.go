package parse

import (
	"testing"

	"github.com/aquasecurity/tracee/types/trace"
)

func TestArgInt32Val(t *testing.T) {
	e := trace.Event{Args: []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "thirty_two_val",
				Type: "int",
			},
			Value: int32(1878),
		},
	}}

	_, err := ArgInt32Val(&e, "thirty_two_val")
	if err != nil {
		t.Errorf(err.Error())
	}

}

func TestArgStringVal(t *testing.T) {
	e := trace.Event{Args: []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "string_val",
				Type: "string",
			},
			Value: "hello_tracee",
		},
	}}

	_, err := ArgStringVal(&e, "string_val")
	if err != nil {
		t.Errorf(err.Error())
	}

}

func TestArgUint64Val(t *testing.T) {
	e := trace.Event{Args: []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "u_sixty_four_val",
				Type: "unsigned int",
			},
			Value: uint64(187818781878),
		},
	}}

	_, err := ArgUint64Val(&e, "u_sixty_four_val")
	if err != nil {
		t.Errorf(err.Error())
	}

}

func TestArgUint32Val(t *testing.T) {
	e := trace.Event{Args: []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "u_thirty_two_val",
				Type: "unsigned int",
			},
			Value: uint32(18781878),
		},
	}}

	_, err := ArgUint32Val(&e, "u_thirty_two_val")
	if err != nil {
		t.Errorf(err.Error())
	}

}

func TestArgStringArrVal(t *testing.T) {
	e := trace.Event{Args: []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "arr_string_val",
				Type: "string",
			},
			Value: []string{"hello", "tracee", "ebpf"},
		},
	}}

	_, err := ArgStringArrVal(&e, "arr_string_val")
	if err != nil {
		t.Errorf(err.Error())
	}

}

func TestArgUlongArrVal(t *testing.T) {
	e := trace.Event{Args: []trace.Argument{
		{
			ArgMeta: trace.ArgMeta{
				Name: "arr_u_sixty_four",
				Type: "unsigned int",
			},
			Value: []uint64{187818781878, 187818781879, 1878187880},
		},
	}}

	_, err := ArgUlongArrVal(&e, "arr_u_sixty_four")
	if err != nil {
		t.Errorf(err.Error())
	}

}
