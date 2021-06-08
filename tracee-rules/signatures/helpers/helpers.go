package helpers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/tracee/external"
)

type ConnectAddrData struct {
	SaFamily string `json:"sa_family"`
	SinPort  string `json:"sin_port"`
	SinAddr  string `json:"sin_addr"`
	SinPort6 string `json:"sin6_port"`
	SinAddr6 string `json:"sin6_addr"`
}

// GetTraceeArgumentByName fetches the argument in event with `Name` that matches argName
func GetTraceeArgumentByName(event tracee.Event, argName string) (tracee.Argument, error) {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg, nil
		}
	}
	return tracee.Argument{}, fmt.Errorf("argument %s not found", argName)
}

// IsFileWrite returns whether or not the passed file permissions string contains
// o_wronly or o_rdwr
func IsFileWrite(flags string) bool {
	flagsLow := strings.ToLower(flags)
	if strings.Contains(flagsLow, "o_wronly") || strings.Contains(flagsLow, "o_rdwr") {
		return true
	}
	return false
}

// GetAddrStructFromArg populates connectData with the value of the addrArg
func GetAddrStructFromArg(addrArg tracee.Argument, connectData *ConnectAddrData) error {
	addrStr := strings.Replace(addrArg.Value.(string), "'", "\"", -1)
	err := json.Unmarshal([]byte(addrStr), &connectData)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	return nil
}

func CheckNewCaps(oldCap int, newCap int) bool{

	convertedOldCap64 := int64(oldCap)
	convertednewCap64 := int64(newCap)
	//Convert to bit mask
	convertedOldCap := strconv.FormatInt(convertedOldCap64, 2)

	arrayOldCap := strings.Split(convertedOldCap, "")

	iterationCount := 64 - len(arrayOldCap)
	for i := 0; i < iterationCount; i++  {
		arrayOldCap = append(arrayOldCap,"0")
	}
	//Convert to bit mask
	convertedNewCap := strconv.FormatInt(convertednewCap64, 2)
	arrayNewCap := strings.Split(convertedNewCap, "")

	iterationCount = 64 - len(arrayNewCap)
	for i := 0; i < iterationCount; i++  {
		arrayNewCap = append(arrayNewCap,"0")
	}

	for i := 0; i < 64; i++  {
		if arrayOldCap[i] == "0" && arrayNewCap[i] == "1"{
			return true
		}
	}
	return false
}
