package ebpf

import (
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/common/errfmt"
)

const (
	ConfigMap = "config_map"
)

// Config mirrors the C struct config_entry (config_entry_t).
//
// Order of fields is important, as it is used as a value for the ConfigMap BPF map, so this
// struct must stay byte-compatible with config_entry_t {tracee_pid, options, cgroup_v1_hid}.
//
// The rule model writes the per-event rules and scope-filter config to its own maps internally
// (PolicyManager.UpdateBPF), so the per-policy policies_version/policies_config that used to live
// in config_entry are gone from both sides.
type Config struct {
	TraceePid   uint32
	Options     uint32
	CgroupV1Hid uint32
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
