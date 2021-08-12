package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tracee "github.com/aquasecurity/tracee/tracee-ebpf/external"
)

const (
	TimeWaitForFileCreation     = 5
	TimeWaitForCaseOfFileLocked = 1
)

type ConnectAddrData struct {
	SaFamily string `json:"sa_family"`
	SinPort  string `json:"sin_port"`
	SinAddr  string `json:"sin_addr"`
	SinPort6 string `json:"sin6_port"`
	SinAddr6 string `json:"sin6_addr"`
}

var systemInfo map[string]interface{}

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

// GetSystemInfo return the system information fetched from tracee-ebpf for signatures use.
func GetSystemInfo() map[string]interface{} {
	return systemInfo
}

// InitSystemInfo initialize the global, and should only be called from the main tracee-rules package.
func InitSystemInfo(systemInfoFilePath string) error {
	var err error
	systemInfo, err = retrieveSystemInfo(systemInfoFilePath)
	return err
}

// retrieveSystemInfo read a file that suppose to contain the system information in json format.
func retrieveSystemInfo(systemInfoFilePath string) (map[string]interface{}, error) {
	systemInfo := make(map[string]interface{})
	systemInfoFile, err := os.Open(systemInfoFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Wait for the file creation by tracee-ebpf if it delays
			time.Sleep(TimeWaitForFileCreation)
		} else {
			// Wait in the case that the file is written right now
			time.Sleep(TimeWaitForCaseOfFileLocked)
		}
		systemInfoFile, err = os.Open(systemInfoFilePath)
		if err != nil {
			return systemInfo, fmt.Errorf("couldn't get system info file - %s", systemInfoFilePath)
		}
	}
	fileContent, _ := io.ReadAll(systemInfoFile)
	_ = systemInfoFile.Close()
	err = json.Unmarshal(fileContent, &systemInfo)
	return systemInfo, err
}
