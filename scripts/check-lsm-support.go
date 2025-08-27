// check-lsm-support checks if BPF LSM (Linux Security Module) is supported
// using the same detection logic as Tracee.
//
// Usage:
//
//	go run ./scripts/check-lsm-support.go        # Simple check
//	go run ./scripts/check-lsm-support.go -v     # Verbose with details
//	go run ./scripts/check-lsm-support.go -q     # Quiet (exit code only)
//
// Exit codes:
//
//	0: BPF LSM is supported
//	1: BPF LSM is not supported
//
// The tool checks three sources:
//  1. Runtime: /sys/kernel/security/lsm (preferred)
//  2. Kernel config: CONFIG_BPF_LSM and CONFIG_LSM
//  3. Boot parameters: /proc/cmdline
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/common/environment"
)

func main() {
	verbose := flag.Bool("v", false, "verbose output")
	quiet := flag.Bool("q", false, "quiet mode (exit code only: 0=supported, 1=not)")
	flag.Parse()

	exitCode := checkLSMSupport(*verbose, *quiet)
	os.Exit(exitCode)
}

func checkLSMSupport(verbose, quiet bool) int {
	// Initialize kernel config
	kernelConfig, _ := environment.InitKernelConfig()

	var getKernelConfigValue environment.KernelConfigValueFunc
	if kernelConfig != nil {
		getKernelConfigValue = func(option environment.KernelConfigOption) (environment.KernelConfigOptionValue, string, error) {
			value := kernelConfig.GetValue(option)
			if value == environment.STRING {
				strValue, err := kernelConfig.GetValueString(option)
				if err != nil {
					return value, "", err
				}
				return value, strValue, nil
			}
			return value, value.String(), nil
		}
	} else {
		getKernelConfigValue = func(environment.KernelConfigOption) (environment.KernelConfigOptionValue, string, error) {
			return environment.UNDEFINED, "", errors.New("kernel config unavailable")
		}
	}

	// Check LSM support
	supported, err := environment.CheckLSMSupport(os.DirFS("/"), getKernelConfigValue)

	if quiet {
		if !supported || err != nil {
			return 1
		}
		return 0
	}

	// Verbose output
	if verbose {
		fmt.Printf("BPF LSM Support: ")
		if supported && err == nil {
			fmt.Println("SUPPORTED ✓")
		} else {
			fmt.Println("NOT SUPPORTED ✗")
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		}

		fmt.Println("\nDetails:")

		// Runtime check
		runtime, runtimeErr := environment.IsLSMSupportedInSecurityFs(os.DirFS("/"))
		fmt.Printf("Runtime (/sys/kernel/security/lsm): ")
		if runtimeErr != nil {
			fmt.Printf("✗ %v\n", runtimeErr)
		} else if runtime {
			fmt.Println("✓ BPF found")
		} else {
			fmt.Println("✗ BPF not found")
		}

		// Kernel config
		if kernelConfig != nil {
			fmt.Printf("Kernel config (%s):\n", kernelConfig.GetKernelConfigFilePath())

			// Check CONFIG_BPF_LSM using helper function
			bpfLsmEnabled, bpfLsmErr := environment.CheckBPFLSMInKernelConfig(getKernelConfigValue)
			fmt.Printf("  CONFIG_BPF_LSM: ")
			if bpfLsmErr != nil {
				fmt.Printf("✗ %v\n", bpfLsmErr)
			} else if bpfLsmEnabled {
				fmt.Println("BUILTIN ✓")
			} else {
				fmt.Println("NOT BUILTIN ✗")
			}

			// Check CONFIG_LSM using helper function
			lsmBpfEnabled, lsmErr := environment.CheckBPFInKernelConfigLSM(getKernelConfigValue)
			fmt.Printf("  CONFIG_LSM: ")
			if lsmErr != nil {
				fmt.Printf("✗ %v\n", lsmErr)
			} else if lsmBpfEnabled {
				fmt.Println("contains 'bpf' ✓")
			} else {
				fmt.Println("does not contain 'bpf' ✗")
			}
		} else {
			fmt.Println("Kernel config: ✗ unavailable")
		}

		// Boot params
		boot, _ := environment.CheckBPFInBootParams(os.DirFS("/"))
		if boot.ParameterFound {
			fmt.Printf("Boot params: ")
			if boot.BPFEnabled {
				fmt.Println("✓ BPF enabled")
			} else {
				fmt.Println("✗ BPF not enabled")
			}
		} else {
			fmt.Println("Boot params: - using defaults")
		}
	} else {
		// Simple output (neither verbose nor quiet)
		if supported && err == nil {
			fmt.Println("BPF LSM: SUPPORTED")
		} else {
			fmt.Println("BPF LSM: NOT SUPPORTED")
		}
	}

	if !supported || err != nil {
		return 1
	}
	return 0
}
