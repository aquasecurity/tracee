package helpers_test

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tracee/libbpfgo/helpers"
)

func ExampleTracePipeListen_usage() {
	go func() {
		err := helpers.TracePipeListen()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}()
}
