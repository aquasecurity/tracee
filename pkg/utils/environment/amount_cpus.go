package environment

import (
	"fmt"
	"os"
	"strings"
)

const possibleCPUsFilePath = "/sys/devices/system/cpu/possible"

func GetCPUAmount() (int, error) {
	possibleCPUsFileContent, err := os.ReadFile(possibleCPUsFilePath)
	if err == nil {
		cpusAmount, err := parsePossibleCPUAmountFromCPUFileFormat(string(possibleCPUsFileContent))
		if err == nil {
			return cpusAmount, nil
		}
	}
	return 0, err
}

const singleValue = 1
const rangeValues = 2
const rangeValuesWithGroups = 4

// parsePossibleCPUAmountFromCPUFileFormat parse the format of /sys/devices/system/cpu files and return the amount of CPUs
// specified. The format expected is according to the bitmap_parselist function in the linux kernel.
// Notice that possible CPUs should be sequential values starting with 0, because the OS gives indexes from 0 onward to
// all possible CPUs.
//
// Note: 'sysconf(_SC_NPROCESSORS_CONF)' is not used because it is found to be broken.
// For more info see thread from libbpf - https://lore.kernel.org/bpf/ef0f23d0-456a-70b0-1ef9-2615a5528278@iogearbox.net/
func parsePossibleCPUAmountFromCPUFileFormat(cpuFileContent string) (int, error) {
	var rangeStart, rangeEnd int
	var usedSize, groupSize int
	bitmapsRegions := strings.Split(cpuFileContent, ",")
	if len(bitmapsRegions) > 1 {
		return 0, fmt.Errorf("possible cpus should be following indexes starting with 0, so multiple regions is not allowed")
	}
	cpusAmount := 0
	n, _ := fmt.Sscanf(bitmapsRegions[0], "%d-%d:%d/%d", &rangeStart, &rangeEnd, &usedSize, &groupSize)
	switch n {
	case singleValue:
		if rangeStart != 0 {
			return 0, fmt.Errorf("possible cpus must start from the index 0, so single CPU index value must be 0")
		}
		cpusAmount = 1
	case rangeValues:
		if rangeStart != 0 {
			return 0, fmt.Errorf("possible cpus should be following indexes range starting with 0")
		}
		cpusAmount = rangeEnd - rangeStart + 1
	case rangeValuesWithGroups:
		return 0, fmt.Errorf("possible cpus should be following indexes, but received groups format")
	default:
		return 0, fmt.Errorf("unknown possible cpu file format")
	}
	return cpusAmount, nil
}
