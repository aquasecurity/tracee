package flags_test

import (
	"testing"

	"github.com/aquasecurity/tracee/cmd/tracee-ebpf/flags"
	"github.com/stretchr/testify/assert"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func TestPrepareCapsConfig(t *testing.T) {
	testCases := []struct {
		Name           string
		Input          []string
		ExpectedResult flags.CapsConfig
		ExpectedError  bool
	}{
		{
			Name:           "No flags",
			Input:          []string{},
			ExpectedResult: flags.CapsConfig{},
			ExpectedError:  false,
		},
		{
			Name:  "Only allow failed drop",
			Input: []string{flags.AllowFailedDropFlag},
			ExpectedResult: flags.CapsConfig{
				AllowHighCaps: true,
			},
			ExpectedError: false,
		},
		{
			Name:  "Only cancel drop",
			Input: []string{flags.CancelDropFlag},
			ExpectedResult: flags.CapsConfig{
				CancelCapsDrop: true,
			},
			ExpectedError: false,
		},
		{
			Name:  "Only add caps",
			Input: []string{flags.AddReqCapsFlag + "=cap_syslog"},
			ExpectedResult: flags.CapsConfig{
				CapsToPreserve: []cap.Value{
					cap.SYSLOG,
				},
			},
			ExpectedError: false,
		},
		{
			Name:  "All flags",
			Input: []string{flags.AllowFailedDropFlag, flags.CancelDropFlag, flags.AddReqCapsFlag + "=cap_syslog"},
			ExpectedResult: flags.CapsConfig{
				AllowHighCaps:  true,
				CancelCapsDrop: true,
				CapsToPreserve: []cap.Value{
					cap.SYSLOG,
				},
			},
			ExpectedError: false,
		},
		{
			Name:           "Illegal flag",
			Input:          []string{"illegal-flag"},
			ExpectedResult: flags.CapsConfig{},
			ExpectedError:  true,
		},
		{
			Name:           "Illegal added cap",
			Input:          []string{flags.AddReqCapsFlag + "=illegal_cap"},
			ExpectedResult: flags.CapsConfig{},
			ExpectedError:  true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			cfg, err := flags.PrepareCapsConfig(testCase.Input)
			if testCase.ExpectedError {
				assert.Error(t, err)
			} else {
				assert.Equal(t, testCase.ExpectedResult.AllowHighCaps, cfg.AllowHighCaps)
				assert.Equal(t, testCase.ExpectedResult.CancelCapsDrop, cfg.CancelCapsDrop)
				assert.ElementsMatch(t, testCase.ExpectedResult.CapsToPreserve, cfg.CapsToPreserve)
			}
		})
	}
}
