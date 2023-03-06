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

func BpfObject(config *tracee.Config, kConfig *helpers.KernelConfig, OSInfo *helpers.OSInfo, installPath string, version string) error {
	var d = struct {
		btfenv     bool
		bpfenv     bool
		btfvmlinux bool
	}{
		btfenv:     false,
		bpfenv:     false,
		btfvmlinux: helpers.OSBTFEnabled(),
	}

	bpfFilePath, err := checkEnvPath("TRACEE_BPF_FILE")
	if bpfFilePath != "" {
		d.bpfenv = true
	} else if bpfFilePath == "" && err != nil {
		return errfmt.WrapError(err)
	}
	btfFilePath, err := checkEnvPath("TRACEE_BTF_FILE")
	if btfFilePath != "" {
		d.btfenv = true
	} else if btfFilePath == "" && err != nil {
		return errfmt.WrapError(err)
	}
	logger.Debugw("BTF", "bpfenv", d.bpfenv, "btfenv", d.btfenv, "vmlinux", d.btfvmlinux)

	var tVersion, kVersion string
	var bpfBytes []byte
	var unpackBTFFile string

	// Decision ordering:

	// (1) BPF file given & BTF (vmlinux or env) exists: always load BPF as CO-RE
	// (2) BPF file given & if no BTF exists: it is a non CO-RE BPF

	if d.bpfenv {
		logger.Debugw("BPF: using BPF object from environment", "file", bpfFilePath)
		if d.btfvmlinux || d.btfenv { // (1)
			if d.btfenv {
				logger.Debugw("BTF: using BTF file from environment", "file", btfFilePath)
				config.BTFObjPath = btfFilePath
			}
		} // else {} (2)
		if bpfBytes, err = os.ReadFile(bpfFilePath); err != nil {
			return errfmt.WrapError(err)
		}

		goto out
	}

	// (3) no BPF file given & BTF (vmlinux or env) exists: load embedded BPF as CO-RE

	if d.btfvmlinux || d.btfenv { // (3)
		logger.Debugw("BPF: using embedded BPF object")
		if d.btfenv {
			logger.Debugw("BTF: using BTF file from environment", "file", btfFilePath)
			config.BTFObjPath = btfFilePath
		}
		bpfFilePath = "embedded-core"
		bpfBytes, err = unpackCOREBinary()
		if err != nil {
			return errfmt.Errorf("could not unpack embedded CO-RE eBPF object: %v", err)
		}

		goto out
	}

	// (4) no BPF file given & no BTF available: check embedded BTF files

	unpackBTFFile = filepath.Join(installPath, "/tracee.btf")
	err = unpackBTFHub(unpackBTFFile, OSInfo)

	if err == nil {
		logger.Debugw("BTF: using BTF file from embedded btfhub", "file", unpackBTFFile)
		config.BTFObjPath = unpackBTFFile
		bpfFilePath = "embedded-core"
		bpfBytes, err = unpackCOREBinary()
		if err != nil {
			return errfmt.Errorf("could not unpack embedded CO-RE eBPF object: %v", err)
		}

		goto out
	}

	// (5) no BPF file given & no BTF available & no embedded BTF: non CO-RE BPF

	tVersion = strings.ReplaceAll(version, "\"", "")
	tVersion = strings.ReplaceAll(tVersion, ".", "_")
	kVersion = OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	kVersion = strings.ReplaceAll(kVersion, ".", "_")

	bpfFilePath = fmt.Sprintf("%s/tracee.bpf.%s.%s.o", installPath, kVersion, tVersion)
	logger.Debugw("BPF: no BTF file was found or provided")
	logger.Debugw("BPF: trying non CO-RE eBPF", "file", bpfFilePath)
	if bpfBytes, err = os.ReadFile(bpfFilePath); err != nil {
		// tell entrypoint that eBPF non CO-RE obj compilation is needed
		logger.Errorw("BPF", "error", err)
		logger.Errorw("BPF: could not load CO-RE eBPF object and could not find non CO-RE object", "installPath", installPath)
		logger.Warnw("BPF: you may build a non CO-RE eBPF object by executing \"make install-bpf-nocore\" in the source tree")
		os.Exit(2)
	}

out:
	config.KernelConfig = kConfig
	config.BPFObjPath = bpfFilePath
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
	b, err := embed.BPFBundleInjected.ReadFile("dist/tracee.bpf.core.o")
	if err != nil {
		return nil, err
	}

	logger.Debugw("Unpacked CO:RE bpf object file into memory")

	return b, nil
}

// unpackBTFHub unpacks tailored, to the compiled eBPF object, BTF files for kernel supported by BTFHub
func unpackBTFHub(outFilePath string, OSInfo *helpers.OSInfo) error {
	var btfFilePath string

	osId := OSInfo.GetOSReleaseFieldValue(helpers.OS_ID)
	versionId := strings.Replace(OSInfo.GetOSReleaseFieldValue(helpers.OS_VERSION_ID), "\"", "", -1)
	kernelRelease := OSInfo.GetOSReleaseFieldValue(helpers.OS_KERNEL_RELEASE)
	arch := OSInfo.GetOSReleaseFieldValue(helpers.OS_ARCH)

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
