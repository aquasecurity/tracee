// Command-line interface for checking LSM BPF support
// Used by e2e checks and standalone verification
// Have to be compiled with -tags lsmsupport after building the LSM check BPF objects
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/pkg/ebpf/lsmsupport"
)

func main() {
	var quiet bool
	flag.BoolVar(&quiet, "q", false, "Suppress output, only return exit code")
	flag.BoolVar(&quiet, "quiet", false, "Suppress output, only return exit code")
	flag.Parse()

	supported, err := lsmsupport.IsLsmBpfSupported()
	var exitCode int
	if err != nil {
		exitCode = 2
	} else if supported {
		exitCode = 0
	} else {
		exitCode = 1
	}

	// In quiet mode, just exit with the code
	if quiet {
		os.Exit(exitCode)
	}

	// Verbose output with formatting
	fmt.Println()
	fmt.Println("==========================================")
	switch exitCode {
	case 0:
		fmt.Println("🎉 SUCCESS: LSM BPF is SUPPORTED!")
		fmt.Println("   Your system has working LSM BPF capability")
		fmt.Println()
		fmt.Println("📋 Summary:")
		fmt.Println("   • LSM check result: ✅ SUPPORTED")
		os.Exit(0)
	case 1:
		fmt.Println("❌ EXPECTED: LSM BPF is NOT SUPPORTED")
		fmt.Println("   This is the correct result for most systems")
		fmt.Println("   (LSM BPF requires specific kernel configuration)")
		fmt.Println()
		fmt.Println("📋 Summary:")
		fmt.Println("   • LSM check result: ❌ NOT SUPPORTED (expected)")
		os.Exit(1)
	case 2:
		fmt.Println("❌ ERROR: LSM BPF check failed")
		fmt.Println("   Error:", err)
		fmt.Println()
		fmt.Println("📋 Summary:")
		fmt.Println("   • LSM check result: ❌ ERROR (support unknown)")
		os.Exit(2)
	}
}
