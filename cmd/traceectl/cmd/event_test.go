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
		{
			TestName:        "events list",
			OutputSlice:     []string{"event", "list", "--format", "json"},
			ExpectedPrinter: "",
			ExpectedError:   nil,
		},
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
		{
			TestName:        "No events enable",
			OutputSlice:     []string{"event", "enable"},
			ExpectedPrinter: nil,
			ExpectedError:   fmt.Errorf("accepts 1 arg(s), received 0"),
		},
		{
			TestName:        "enable event",
			OutputSlice:     []string{"event", "enable", "event"},
			ExpectedPrinter: "Enabled event: event",
			ExpectedError:   nil,
		},
		{
			TestName:        "No disable events",
			OutputSlice:     []string{"event", "disable"},
			ExpectedPrinter: nil,
			ExpectedError:   fmt.Errorf("accepts 1 arg(s), received 0"),
		},
		{
			TestName:        "disable event",
			OutputSlice:     []string{"event", "disable", "event"},
			ExpectedPrinter: "Disabled event: event",
			ExpectedError:   nil,
		},
	}
	for _, testCase := range eventTests {
		t.Run(testCase.TestName, func(t *testing.T) { test.TestCommand(t, testCase, rootCmd) })
	}
}
