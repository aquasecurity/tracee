package system

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/common/environment"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/timeutil"
	traceeversion "github.com/aquasecurity/tracee/pkg/version"
)

const initProcNsDir = "/proc/1/ns"

// CollectSystemInfo gathers immutable system information at startup
func CollectSystemInfo() (*datastores.SystemInfo, error) {
	info := &datastores.SystemInfo{}

	// Architecture
	arch, err := environment.UnameMachine()
	if err != nil {
		return nil, errfmt.Errorf("failed to get architecture: %v", err)
	}
	info.Architecture = arch

	// Kernel release
	kernelRelease, err := environment.UnameRelease()
	if err != nil {
		return nil, errfmt.Errorf("failed to get kernel release: %v", err)
	}
	info.KernelRelease = kernelRelease

	// Hostname
	hostname, err := os.Hostname()
	if err != nil {
		return nil, errfmt.Errorf("failed to get hostname: %v", err)
	}
	info.Hostname = hostname

	// Boot time
	info.BootTime = timeutil.GetBootTime()

	// OS information
	osInfo, err := environment.GetOSInfo()
	if err != nil {
		return nil, errfmt.Errorf("failed to get OS info: %v", err)
	}

	// Extract OS fields from osInfo
	info.OSName = osInfo.GetOSReleaseFieldValue(environment.OS_NAME)
	info.OSVersion = osInfo.GetOSReleaseFieldValue(environment.OS_VERSION)
	info.OSPrettyName = osInfo.GetOSReleaseFieldValue(environment.OS_PRETTY_NAME)

	// Tracee version
	info.TraceeVersion = traceeversion.GetVersion()

	// Init namespaces
	info.InitNamespaces = fetchInitNamespaces()

	return info, nil
}

// fetchInitNamespaces fetches the namespace values from the /proc/1/ns directory
// This is adapted from pkg/events/usermode.go's fetchInitNamespaces function
func fetchInitNamespaces() map[string]uint32 {
	initNamespacesMap := make(map[string]uint32)
	namespaceValueReg := regexp.MustCompile(`:\[[[:digit:]]+\]`)

	namespacesLinks, err := os.ReadDir(initProcNsDir)
	if err != nil {
		// Return empty map on error rather than failing - init namespaces are informational
		return initNamespacesMap
	}

	for _, namespaceLink := range namespacesLinks {
		linkString, err := os.Readlink(filepath.Join(initProcNsDir, namespaceLink.Name()))
		if err != nil {
			continue
		}
		trim := strings.Trim(namespaceValueReg.FindString(linkString), "[]:")
		namespaceNumber, err := strconv.ParseUint(trim, 10, 32)
		if err != nil {
			continue
		}
		initNamespacesMap[namespaceLink.Name()] = uint32(namespaceNumber)
	}

	return initNamespacesMap
}
