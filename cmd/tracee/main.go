package main

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/cmd/tracee/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
