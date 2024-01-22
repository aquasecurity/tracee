package ebpf

import (
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/errfmt"
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
func (c *Config) UpdateBPF(bpfModule *bpf.Module) error {
	bpfConfigMap, err := bpfModule.GetMap(ConfigMap)
	if err != nil {
		return errfmt.WrapError(err)
	}

	cZero := uint32(0)
	if err = bpfConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(c)); err != nil {
		return errfmt.WrapError(err)
	}

	return nil
}
