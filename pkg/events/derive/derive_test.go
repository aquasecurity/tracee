package derive

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingleEventDeriveFunc(t *testing.T) {
	testEventID := events.ID(0)

	// Change getter of the events.Event to give the test definition
	def := events.Definitions.Get(testEventID)
	def.Params = []trace.ArgMeta{
		{
			Name: "arg1",
			Type: "int",
		},
		{
			Name: "arg2",
			Type: "int",
		},
	}
	savedEventDefFunc := getEventDefFunc
	defer func() {
		getEventDefFunc = savedEventDefFunc
	}()
	getEventDefFunc = func(id events.ID) events.Event {
		return def
	}

	baseEvent := getTestEvent()

	successfulDeriveEventDeriveArgsFunc := func(event trace.Event) ([]interface{}, error) {
		return []interface{}{1, 2}, nil
	}
	noDeriveEventDeriveArgsFunc := func(event trace.Event) ([]interface{}, error) {
		return nil, nil
	}
	deriveArgsError := "fail derive args"
	failDeriveArgsFunc := func(event trace.Event) ([]interface{}, error) {
		return nil, fmt.Errorf(deriveArgsError)
	}
	illegalDeriveArgsFunc := func(event trace.Event) ([]interface{}, error) {
		return []interface{}{1, 2, 3}, nil
	}

	testCases := []struct {
		Name                string
		ExpectedError       string
		ArgsDeriveFunc      deriveArgsFunction
		DerivedEventsAmount int
	}{
		{
			Name:                "Hapfapy flow - derive event",
			ExpectedError:       "",
			ArgsDeriveFunc:      successfulDeriveEventDeriveArgsFunc,
			DerivedEventsAmount: 1,
		},
		{
			Name:                "Happy flow - don't derive event",
			ExpectedError:       "",
			ArgsDeriveFunc:      noDeriveEventDeriveArgsFunc,
			DerivedEventsAmount: 0,
		},
		{
			Name:                "Fail derive argument function",
			ExpectedError:       deriveArgsError,
			ArgsDeriveFunc:      failDeriveArgsFunc,
			DerivedEventsAmount: 0,
		},
		{
			Name:                "Fail new event creation",
			ExpectedError:       fmt.Sprintf("error while building derived event '%s' - expected %d arguments but given %d", def.Name, len(def.Params), 3),
			ArgsDeriveFunc:      illegalDeriveArgsFunc,
			DerivedEventsAmount: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			deriveFunc := singleEventDeriveFunc(testEventID, testCase.ArgsDeriveFunc)
			derivedEvents, errs := deriveFunc(baseEvent)
			assert.Len(t, derivedEvents, testCase.DerivedEventsAmount)
			if testCase.ExpectedError != "" {
				assert.ErrorContains(t, errs[0], testCase.ExpectedError)
				return
			}
			require.Empty(t, errs)
		})
	}
}

func TestNewEvent(t *testing.T) {
	baseEvent := getTestEvent()
	skeleton := eventSkeleton{
		Name: "test_derive",
		ID:   124,
		Params: []trace.ArgMeta{
			{
				Name: "arg1",
				Type: "int",
			},
			{
				Name: "arg2",
				Type: "string",
			},
		},
	}

	testCases := []struct {
		Name        string
		Args        []interface{}
		ExpectError bool
	}{
		{
			Name:        "normal flow",
			Args:        []interface{}{1, "test"},
			ExpectError: false,
		},
		{
			Name:        "less arguments than expected",
			Args:        []interface{}{1},
			ExpectError: true,
		},
		{
			Name:        "more arguments than expected",
			Args:        []interface{}{1, "test", 2},
			ExpectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			evt, err := newEvent(&baseEvent, skeleton, testCase.Args)
			if testCase.ExpectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, skeleton.Name, evt.EventName)
			assert.Equal(t, skeleton.ID, evt.EventID)
			require.Len(t, evt.Args, len(testCase.Args))
			for i, arg := range evt.Args {
				assert.Equal(t, skeleton.Params[i], arg.ArgMeta)
				assert.Equal(t, testCase.Args[i], arg.Value)
			}
			temp := evt
			temp.EventName = baseEvent.EventName
			temp.EventID = baseEvent.EventID
			temp.Args = baseEvent.Args
			temp.ArgsNum = baseEvent.ArgsNum
			temp.StackAddresses = baseEvent.StackAddresses
			temp.ReturnValue = baseEvent.ReturnValue
			assert.Equal(t, baseEvent, temp)
		})
	}
}

func getTestEvent() trace.Event {
	return trace.Event{
		Timestamp:           100000,
		ProcessorID:         1,
		ProcessID:           13,
		CgroupID:            12345,
		ThreadID:            13,
		ParentProcessID:     12,
		HostProcessID:       13,
		HostThreadID:        13,
		HostParentProcessID: 12,
		UserID:              1,
		MountNS:             12345,
		PIDNS:               23456,
		ProcessName:         "test",
		HostName:            "test",
		ContainerID:         "test",
		ContainerImage:      "test",
		ContainerName:       "test",
		PodName:             "test",
		PodNamespace:        "test",
		PodUID:              "test",
		EventID:             123,
		EventName:           "test_event",
		ArgsNum:             1,
		ReturnValue:         1,
		StackAddresses:      []uint64{4444},
		Args: []trace.Argument{
			{
				ArgMeta: trace.ArgMeta{
					Name: "test-arg",
					Type: "int",
				},
				Value: 1111,
			},
		},
	}
}
