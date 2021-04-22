package helpers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetProcGZConfigByPath(t *testing.T) {
	testCases := []struct {
		name           string
		goldenFilePath string
		expectedMap    KernelConfig
		expectedError  error
	}{
		{
			name:           "non-existant",
			goldenFilePath: "foobarblahblahblah",
			expectedMap:    KernelConfig{},
			expectedError:  errors.New("could not open foobarblahblahblah: open foobarblahblahblah: no such file or directory"),
		},
		{
			name:           "invalid zip format",
			goldenFilePath: "testdata/tarred_config.tar",
			expectedMap:    KernelConfig{},
			expectedError:  errors.New("gzip: invalid header"),
		},
		{
			name:           "standard config",
			goldenFilePath: "testdata/config_standard.gz",
			expectedMap:    KernelConfig{CONFIG_BPF: "y", CONFIG_BPF_JIT_ALWAYS_ON: "y", CONFIG_BPF_LSM: "y", CONFIG_BPF_PRELOAD: "y", CONFIG_BPF_PRELOAD_UMD: "m", CONFIG_BPF_SYSCALL: "y", CONFIG_IPV6_SEG6_BPF: "y", CONFIG_NETFILTER_XT_MATCH_BPF: "m"},
			expectedError:  nil,
		},
		{
			name:           "config with comments in it",
			goldenFilePath: "testdata/comments_config.gz",
			expectedMap:    KernelConfig{CONFIG_BPF: "y", CONFIG_BPF_SYSCALL: "y", CONFIG_BPF_PRELOAD_UMD: "m"},
			expectedError:  nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {

			var kconfig KernelConfig = make(map[uint32]string)
			err := kconfig.getProcGZConfigByPath(tt.goldenFilePath)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedMap, kconfig)
		})
	}
}

func TestGetKernelConfigValue(t *testing.T) {
	testCases := []struct {
		name          string
		key           uint32
		conf          KernelConfig
		expectedError error
		expectedValue string
	}{
		{
			name:          "Value present",
			key:           CONFIG_BPF,
			conf:          KernelConfig{CONFIG_BPF: "y"},
			expectedError: nil,
			expectedValue: "y",
		},
		{
			name:          "Value present",
			key:           CONFIG_BPF,
			conf:          KernelConfig{CONFIG_BPFILTER: "foo", CONFIG_BPF: "y"},
			expectedError: nil,
			expectedValue: "y",
		},
		{
			name:          "nil conf",
			key:           CONFIG_BPF,
			conf:          nil,
			expectedError: errors.New("kernel config value does not exist, it's possible this option is not present in your kernel version or the KernelConfig has not been initialized"),
			expectedValue: "",
		},
		{
			name:          "Value not present",
			key:           CONFIG_BPF_JIT,
			conf:          KernelConfig{CONFIG_BPF: "y"},
			expectedError: errors.New("kernel config value does not exist, it's possible this option is not present in your kernel version or the KernelConfig has not been initialized"),
			expectedValue: "",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			v, err := tt.conf.GetKernelConfigValue(tt.key)
			assert.Equal(t, tt.expectedError, err)
			assert.Equal(t, tt.expectedValue, v)
		})
	}
}
