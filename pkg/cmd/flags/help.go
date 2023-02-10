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
		"trace",
		"capabilities",
		"rego",
		"log",
	}

	if newBinary {
		keys = append(keys, "output")
	} else {
		keys = append(keys, "outputOld")
	}

	for _, k := range keys {
		if checkIsHelp(ctx, k) {
			fmt.Print(getHelpString(k))
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

func getHelpString(key string) string {
	switch key {
	case "crs":
		return containersHelp()
	case "cache":
		return cacheHelp()
	case "capture":
		return captureHelp()
	case "trace":
		return filterHelp()
	case "output":
		return outputHelp()
	case "outputOld":
		return outputHelpOld()
	case "capabilities":
		return capabilitiesHelp()
	case "rego":
		return regoHelp()
	case "log":
		return logHelp()
	}
	return ""
}
