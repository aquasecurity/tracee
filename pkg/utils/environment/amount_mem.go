package environment

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// GetMEMAmountInMBs reads meminfo file and returns MemTotal in megabytes
func GetMEMAmountInMBs() int {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() {
		_ = file.Close()
	}()
	scanner := bufio.NewScanner(file)

	var value int
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), ":")
		if strings.Contains(line[0], "MemTotal") {
			_, _ = fmt.Sscanf(line[1], "%d kB", &value)
			return value / 1024
		}
	}

	return 0
}
