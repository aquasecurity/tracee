package main

import (
	"encoding/json"
	"fmt"
	"strings"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
)

type connectAddrData struct {
	SaFamily string `json:"sa_family"`
	SinPort  string `json:"sin_port"`
	SinAddr  string `json:"sin_addr"`
	SinPort6 string `json:"sin6_port"`
	SinAddr6 string `json:"sin6_addr"`
}

func GetTraceeArgumentByName(event tracee.Event, argName string) (tracee.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return tracee.Argument{}, fmt.Errorf("argument %s not found", argName)
}

func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

func GetAddrStructFromArg(addrArg tracee.Argument, connectData *connectAddrData) error {
	addrStr := strings.Replace(addrArg.Value.(string), "'", "\"", -1)
	err := json.Unmarshal([]byte(addrStr), &connectData)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}
