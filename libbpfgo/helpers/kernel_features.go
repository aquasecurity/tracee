package helpers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type KernelConfig map[string]string

// InitKernelConfig populates the passed KernelConfig
// by attempting to read the kernel config into it from:
// /proc/config-$(uname -r)
// or
// /boot/config.gz
func InitKernelConfig(k KernelConfig) (KernelConfig, error) {

	err := k.getBootConfig()
	if err == nil {
		return k, nil
	}

	err2 := k.getProcGZConfig()
	if err != nil {
		return nil, fmt.Errorf("%v %v", err, err2)
	}

	return k, nil
}

// GetKernelConfigValue retrieves a value from the kernel config
// If the config value does not exist an error will be returned
func (k KernelConfig) GetKernelConfigValue(key string) (string, error) {
	v, exists := k[key]
	if !exists {
		return "", errors.New("kernel config value does not exist, it is could not be known by your kernel version")
	}
	return v, nil
}

func (k KernelConfig) getBootConfig() error {

	x := unix.Utsname{}
	err := unix.Uname(&x)
	if err != nil {
		return fmt.Errorf("could not determine uname release: %v", err)
	}

	bootConfigPath := fmt.Sprintf("/boot/config-%s", bytes.Trim(x.Release[:], "\x00"))

	configFile, err := os.Open(bootConfigPath)
	if err != nil {
		return fmt.Errorf("could not open %s: %v", bootConfigPath, err)
	}

	scanner := bufio.NewScanner(configFile)
	k.readConfigFromScanner(scanner)
	configFile.Close()

	return nil
}

func (k KernelConfig) getProcGZConfig() error {

	procConfigPath := "/proc/config.gz"

	configFile, err := os.Open(procConfigPath)
	if err != nil {
		return fmt.Errorf("could not open %s: %v", procConfigPath, err)
	}

	zreader, err := gzip.NewReader(configFile)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(zreader)
	k.readConfigFromScanner(scanner)
	configFile.Close()

	return nil
}

func (k KernelConfig) readConfigFromScanner(scanner *bufio.Scanner) {
	for scanner.Scan() {
		kv := strings.Split(scanner.Text(), "=")
		if len(kv) != 2 {
			continue
		}

		k[kv[0]] = kv[1]
	}
}
