package flags

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func PrintAndExitIfHelp(ctx *cli.Context, newBinary bool) {
	keys := []string{
		"crs",
		"cache",
		"capture",
		"filter",
		"output",
		"capabilities",
		"rego",
		"log",
	}

	for _, k := range keys {
		if checkIsHelp(ctx, k) {
			fmt.Print(GetHelpString(k, newBinary))
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

func GetHelpString(key string, newBinary bool) string {
	switch key {
	case "config":
		return configHelp()
	case "crs":
		return containersHelp()
	case "cache":
		return cacheHelp()
	case "capture":
		return captureHelp()
	case "filter":
		return filterHelp()
	case "output":
		if newBinary {
			return outputHelp()
		}
		return traceeEbpfOutputHelp()
	case "capabilities":
		return capabilitiesHelp()
	case "rego":
		return regoHelp()
	case "log":
		return logHelp()
	}
	return ""
}
