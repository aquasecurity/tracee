package initialize

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/libbpfgo/helpers"

	embed "github.com/aquasecurity/tracee"
	tracee "github.com/aquasecurity/tracee/pkg/ebpf"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// BpfObject sets up and configures a BPF object for tracing and monitoring
// system events within the kernel. It takes pointers to tracee.Config,
// helpers.KernelConfig, and helpers.OSInfo structures, as well as an
// installation path and a version string. The function unpacks the CO-RE eBPF
// object binary, checks if BTF is enabled, unpacks the BTF file from BTF Hub if
// necessary, and assigns the kernel configuration and BPF object bytes.
func BpfObject(config *tracee.Config, kConfig *helpers.KernelConfig, osInfo *helpers.OSInfo, installPath string, version string) error {
	btfFilePath, err := checkEnvPath("TRACEE_BTF_FILE")
	if btfFilePath == "" && err != nil {
		return errfmt.WrapError(err)
	}
	if btfFilePath != "" {
		logger.Debugw("BTF", "BTF environment variable set", "path", btfFilePath)
		config.BTFObjPath = btfFilePath
	}

	bpfBytes, err := unpackCOREBinary()
	if err != nil {
		return errfmt.Errorf("could not unpack CO-RE eBPF object: %v", err)
	}

	// BTF unavailable: check embedded BTF files
	if !helpers.OSBTFEnabled() && btfFilePath != "" {
		unpackBTFFile := filepath.Join(installPath, "/tracee.btf")
		err = unpackBTFHub(unpackBTFFile, osInfo)
		if err == nil {
			logger.Debugw("BTF: btfhub embedded BTF file", "file", unpackBTFFile)
			config.BTFObjPath = unpackBTFFile
		} else {
			logger.Debugw("BTF: error unpacking embedded BTFHUB file", "error", err)
		}
	}

	config.KernelConfig = kConfig
	config.BPFObjBytes = bpfBytes

	return nil
}

func checkEnvPath(env string) (string, error) {
	filePath, _ := os.LookupEnv(env)
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err != nil {
			return "", errfmt.Errorf("could not open %s %s", env, filePath)
		}
		return filePath, nil
	}
	return "", nil
}

func unpackCOREBinary() ([]byte, error) {
	b, err := embed.BPFBundleInjected.ReadFile("dist/tracee.bpf.o")
	if err != nil {
		return nil, err
	}

	logger.Debugw("Unpacked CO:RE bpf object file into memory")

	return b, nil
}

// unpackBTFHub extracts an embedded BTFHub file for the given OS and saves it
// to the specified output file path. It first creates a temporary directory if
// it does not already exist, then opens the embedded file and copies its
// contents to the output file. It takes in an output file path as a string and
// an OSInfo struct containing information about the OS, including OS ID,
// version ID, kernel release, and architecture. It returns an error if any of
// the directory creation, file opening, or file copying operations fail.
func unpackBTFHub(outFilePath string, osInfo *helpers.OSInfo) error {
	var btfFilePath string

	osId := osInfo.GetOSReleaseFieldValue(helpers.OS_ID)
	versionId := strings.Replace(osInfo.GetOSReleaseFieldValue(helpers.OS_VERSION_ID), "\"", "", -1)
	kernelRelease := osInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	arch := osInfo.GetOSReleaseFieldValue(helpers.OS_ARCH)

	if err := os.MkdirAll(filepath.Dir(outFilePath), 0755); err != nil {
		return errfmt.Errorf("could not create temp dir: %s", err.Error())
	}

	btfFilePath = fmt.Sprintf("dist/btfhub/%s/%s/%s/%s.btf", osId, versionId, arch, kernelRelease)
	btfFile, err := embed.BPFBundleInjected.Open(btfFilePath)
	if err != nil {
		return errfmt.Errorf("error opening embedded btfhub file: %s", err.Error())
	}
	defer func() {
		if err := btfFile.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return errfmt.Errorf("could not create btf file: %s", err.Error())
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			logger.Errorw("Closing file", "error", err)
		}
	}()

	if _, err := io.Copy(outFile, btfFile); err != nil {
		return errfmt.Errorf("error copying embedded btfhub file: %s", err.Error())
	}

	return nil
}
