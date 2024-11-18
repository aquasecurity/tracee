package cmd

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/test"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/models"
)

func TestEvent(t *testing.T) {
	eventTests := []models.TestCase{
		{
			TestName:        "event",
			OutputSlice:     []string{"event"},
			ExpectedPrinter: nil,
			ExpectedError:   fmt.Errorf("requires at least 1 arg(s), only received 0"),
		},

		//event list
		{
			TestName:        "events list",
			OutputSlice:     []string{"event", "list", "--format", "json"},
			ExpectedPrinter: "",
			ExpectedError:   nil,
		},

		//event describe
		{
			TestName:        "No events describe",
			OutputSlice:     []string{"event", "describe", "--format", "json"},
			ExpectedPrinter: nil,
			ExpectedError:   fmt.Errorf("accepts 1 arg(s), received 0"),
		},
		{
			TestName:        "describe <event_test1>",
			OutputSlice:     []string{"event", "describe", "event_test1", "--format", "json"},
			ExpectedPrinter: "event_test1",
			ExpectedError:   nil,
		},
		//event enable
		{
			TestName:        "No events enable",
			OutputSlice:     []string{"event", "enable"},
			ExpectedPrinter: nil,
			ExpectedError:   fmt.Errorf("accepts 1 arg(s), received 0"), // Update expected output

		},
		{
			TestName:        "enable event",
			OutputSlice:     []string{"event", "enable", "event"},
			ExpectedPrinter: "Enabled event: event",
			ExpectedError:   nil,
		},
		//event disable
		{
			TestName:        "No disable events",
			OutputSlice:     []string{"event", "disable"},
			ExpectedPrinter: nil,
			ExpectedError:   fmt.Errorf("accepts 1 arg(s), received 0"), // Update expected output
		},
		{
			TestName:        "disable event",
			OutputSlice:     []string{"event", "disable", "event"},
			ExpectedPrinter: "Disabled event: event",
			ExpectedError:   nil,
		},
		//event run
		//TODO: add test when support run is added
	}

	for _, testCase := range eventTests {
		t.Run(testCase.TestName, func(t *testing.T) { test.TestCommand(t, testCase, rootCmd) })
	}
}
