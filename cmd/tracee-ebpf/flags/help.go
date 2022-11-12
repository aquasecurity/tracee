package flags

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func PrintAndExitIfHelp(ctx *cli.Context) {
	keys := []string{
		"crs",
		"cache",
		"capture",
		"trace",
		"output",
		"capabilities",
		"rego",
	}

	for _, k := range keys {
		stringSlice := ctx.StringSlice(k)
		if checkIsHelp(stringSlice) {
			fmt.Print(getHelpString(k))
			os.Exit(0)
		}
	}
}

func checkIsHelp(s []string) bool {
	if len(s) == 1 && s[0] == "help" {
		return true
	}
	return false
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
	case "capabilities":
		return capabilitiesHelp()
	case "rego":
		return regoHelp()
	}
	return ""
}
