package environment

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKernelConfigValue(t *testing.T) {
	allConfigFiles := []string{"testdata/config_standard.gz", "testdata/config_comments.gz", "testdata/config_comments"}

	testCases := []struct {
		testName       string
		givenOptions   []KernelConfigOption
		givenValues    []interface{}        // might either be KernelConfigOptionValue or String
		missingOptions []KernelConfigOption // options that will be missing from given config files
	}{
		{
			testName:       "option ok",
			givenOptions:   []KernelConfigOption{CONFIG_BPF},
			givenValues:    []interface{}{BUILTIN},
			missingOptions: []KernelConfigOption{},
		},
		{
			testName:       "multiple options ok",
			givenOptions:   []KernelConfigOption{CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_TEST_BPF, CONFIG_HZ},
			givenValues:    []interface{}{BUILTIN, BUILTIN, MODULE, "250"},
			missingOptions: []KernelConfigOption{},
		},
		{
			testName:       "multiple options ok with single not ok",
			givenOptions:   []KernelConfigOption{CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_TEST_BPF, CONFIG_HZ},
			givenValues:    []interface{}{MODULE, BUILTIN, MODULE, "250"},
			missingOptions: []KernelConfigOption{CONFIG_BPF},
		},
		{
			testName:       "multiple options ok with multiple not ok",
			givenOptions:   []KernelConfigOption{CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_TEST_BPF, CONFIG_HZ, CONFIG_HZ},
			givenValues:    []interface{}{MODULE, BUILTIN, MODULE, "250", "500"},
			missingOptions: []KernelConfigOption{CONFIG_BPF, CONFIG_HZ},
		},
		{
			testName:       "undefined value",
			givenOptions:   []KernelConfigOption{0xFFFFFFFF},
			givenValues:    []interface{}{UNDEFINED}, // non-existing values will be ignored
			missingOptions: []KernelConfigOption{},
		},
	}

	for _, tt := range testCases { // for each of the test cases run:
		t.Run(tt.testName, func(test *testing.T) { // a test named testName with the following func():
			for _, configFile := range allConfigFiles {
				var err error

				// initialize the KernelConfig object
				config := KernelConfig{}
				err = config.initKernelConfig(configFile)
				assert.Equal(test, err, nil)

				// add needed KernelConfigOptions
				for pos, option := range tt.givenOptions {
					config.AddNeeded(option, tt.givenValues[pos])
				}

				// check amount of missing KernelConfigOptions first
				missing := config.CheckMissing()
				assert.Equal(test, len(tt.missingOptions), len(missing))

				// check if missing KernelConfigOptions are the correct ones
				assert.ElementsMatch(test, tt.missingOptions, missing)
			}
		})
	}
}
