package ebpf

import (
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/extensions"
	"github.com/aquasecurity/tracee/pkg/policy"
)

const (
	ConfigMap = "config_map"
)

// Config mirrors the C struct config_entry (config_entry_t).
//
// Order of fields is important, as it is used as a value for
// the ConfigMap BPF map.
type Config struct {
	TraceePid       uint32
	Options         uint32
	CgroupV1Hid     uint32
	_               uint16 // padding free for further use
	PoliciesVersion uint16
	PoliciesConfig  policy.PoliciesConfig
}

// UpdateBPF updates the ConfigMap BPF map with the current config.
func (c *Config) UpdateBPF() error {
	bpfConfigMap, err := extensions.Modules.Get("core").GetMap(ConfigMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	cZero := uint32(0)
	if err = bpfConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(c)); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}
