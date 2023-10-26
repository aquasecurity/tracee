package flags

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

// PrintAndExitIfHelp checks if any of the help flags are set and prints the relevant help message.
// It is used only by the old binary (tracee-ebpf).
func PrintAndExitIfHelp(ctx *cli.Context) {
	keys := []string{
		"cri",
		"cache",
		"proctree",
		"capture",
		"scope",
		"events",
		"output",
		"capabilities",
		"rego",
		"log",
	}

	for _, k := range keys {
		if checkIsHelp(ctx, k) {
			fmt.Print(GetHelpString(k))
			os.Exit(0)
		}
	}
}

// checkIsHelp checks if a flag value is set as "help"
func checkIsHelp(ctx *cli.Context, k string) bool {
	values := ctx.StringSlice(k)
	v := ""
	if len(values) == 1 {
		v = values[0]
	} else {
		v = ctx.String(k)
	}

	return v == "help"
}

func GetHelpString(key string) string {
	switch key {
	case "config":
		return configHelp()
	case "cri":
		return containersHelp()
	case "cache":
		return cacheHelp()
	case "proctree":
		return procTreeHelp()
	case "capture":
		return captureHelp()
	case "scope", "events":
		return filterHelp()
	case "output":
		return outputHelp()
	case "capabilities":
		return capabilitiesHelp()
	case "rego":
		return regoHelp()
	case "log":
		return logHelp()
	}
	return ""
}
