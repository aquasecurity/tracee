package derive

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DeriveEvent(t *testing.T) {
	testEventID := events.ID(1)
	failEventID := events.ID(11)
	deriveEventID := events.ID(12)
	noDerivationEventID := events.ID(13)
	alwaysDeriveError := func() deriveFunction {
		return func(e trace.Event) ([]trace.Event, []error) {
			return []trace.Event{}, []error{fmt.Errorf("derive error")}
		}
	}
	mockDerivationTable := Table{
		testEventID: {
			failEventID: {
				DeriveFunction: alwaysDeriveError(),
				Enabled:        true,
			},
			deriveEventID: {
				DeriveFunction: func(e trace.Event) ([]trace.Event, []error) {
					return []trace.Event{
						{
							EventID: int(deriveEventID),
						},
					}, nil
				},
				Enabled: true,
			},
			noDerivationEventID: {
				DeriveFunction: func(e trace.Event) ([]trace.Event, []error) {
					return []trace.Event{}, nil
				},
				Enabled: true,
			},
		},
	}

	testCases := []struct {
		name            string
		event           trace.Event
		expectedDerived []trace.Event
		expectedErrors  []error
	}{
		{
			name: "derive test event check for all cases",
			event: trace.Event{
				EventID: int(testEventID),
			},
			expectedDerived: []trace.Event{
				{
					EventID: int(deriveEventID),
				},
			},
			expectedErrors: []error{deriveError(failEventID, fmt.Errorf("derive error"))},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			derived, errors := DeriveEvent(tc.event, mockDerivationTable)
			assert.Equal(t, tc.expectedDerived, derived)
			assert.Equal(t, tc.expectedErrors, errors)
		})
	}
}

func Test_DeriveSingleEvent(t *testing.T) {
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

	// store the original getEventDefinition function
	savedEventDefFunc := getEventDefinition
	// switch it back after test is over
	defer func() {
		getEventDefinition = savedEventDefFunc
	}()

	// mock the getEventDefinition function
	getEventDefinition = func(id events.ID) events.Event {
		return def
	}

	baseEvent := getTestEvent()

	successfulDeriveEventArgs := func(event trace.Event) ([]interface{}, error) {
		return []interface{}{1, 2}, nil
	}
	noDeriveEventArgs := func(event trace.Event) ([]interface{}, error) {
		return nil, nil
	}
	deriveArgsError := fmt.Errorf("fail derive args")
	failDeriveEventArgs := func(event trace.Event) ([]interface{}, error) {
		return nil, deriveArgsError
	}
	illegalDeriveEventArgs := func(event trace.Event) ([]interface{}, error) {
		return []interface{}{1, 2, 3}, nil
	}

	testCases := []struct {
		Name                string
		ExpectedError       error
		ArgsDeriveFunc      deriveArgsFunction
		DerivedEventsAmount int
	}{
		{
			Name:                "happy flow - derive event",
			ArgsDeriveFunc:      successfulDeriveEventArgs,
			DerivedEventsAmount: 1,
		},
		{
			Name:                "happy flow - don't derive event",
			ArgsDeriveFunc:      noDeriveEventArgs,
			DerivedEventsAmount: 0,
		},
		{
			Name:                "sad flow - derive arguments fails",
			ExpectedError:       deriveArgsError,
			ArgsDeriveFunc:      failDeriveEventArgs,
			DerivedEventsAmount: 0,
		},
		{
			Name:                "sad flow - unexpected argument count",
			ExpectedError:       unexpectedArgCountError(def.Name, len(def.Params), 3),
			ArgsDeriveFunc:      illegalDeriveEventArgs,
			DerivedEventsAmount: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			deriveFunc := deriveSingleEvent(testEventID, testCase.ArgsDeriveFunc)
			derivedEvents, errs := deriveFunc(baseEvent)
			assert.Len(t, derivedEvents, testCase.DerivedEventsAmount)
			if testCase.ExpectedError != nil {
				assert.Error(t, errs[0], testCase.ExpectedError)
				return
			}
			require.Empty(t, errs)
		})
	}
}

func TestNewEvent(t *testing.T) {
	baseEvent := getTestEvent()
	skeleton := deriveBase{
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
			evt, err := buildDerivedEvent(&baseEvent, skeleton, testCase.Args)
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
