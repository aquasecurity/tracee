package initialize

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	embed "github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
)

// BpfObject sets up and configures a BPF object for tracing and monitoring
// system events within the kernel. It takes pointers to tracee.Config,
// environment.KernelConfig, and environment.OSInfo structures, as well as an
// installation path and a version string. The function unpacks the CO-RE eBPF
// object binary, checks if BTF is enabled, unpacks the BTF file from BTF Hub if
// necessary, and assigns the kernel configuration and BPF object bytes.
func BpfObject(cfg *config.Config, kConfig *environment.KernelConfig, osInfo *environment.OSInfo, installPath string, version string) error {
	btfFilePath, err := checkEnvPath("TRACEE_BTF_FILE")
	if btfFilePath == "" && err != nil {
		return errfmt.WrapError(err)
	}

	if btfFilePath != "" {
		logger.Debugw("BTF", "BTF environment variable set", "path", btfFilePath)
		cfg.BTFObjPath = btfFilePath
	}

	bpfBytes, err := unpackCOREBinary()
	if err != nil {
		return errfmt.Errorf("could not unpack CO-RE eBPF object: %v", err)
	}

	// BTF unavailable: check embedded BTF files

	if !environment.OSBTFEnabled() && btfFilePath == "" {
		unpackBTFFile := filepath.Join(installPath, "/tracee.btf")
		err = unpackBTFHub(unpackBTFFile, osInfo)
		if err == nil {
			logger.Debugw("BTF: btfhub embedded BTF file", "file", unpackBTFFile)
			cfg.BTFObjPath = unpackBTFFile
		} else {
			logger.Debugw("BTF: error unpacking embedded BTFHUB file", "error", err)
		}
	}

	cfg.KernelConfig = kConfig
	cfg.BPFObjBytes = bpfBytes

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
func unpackBTFHub(outFilePath string, osInfo *environment.OSInfo) error {
	var btfFilePath string

	osId := osInfo.GetOSReleaseFieldValue(environment.OS_ID)
	versionId := strings.Replace(osInfo.GetOSReleaseFieldValue(environment.OS_VERSION_ID), "\"", "", -1)
	kernelRelease := osInfo.GetOSReleaseFieldValue(environment.OS_KERNEL_RELEASE)
	arch := osInfo.GetOSReleaseFieldValue(environment.OS_ARCH)

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
