package mount

import (
	"bufio"
	"os"
	"strings"
)

// IsMountpoint searches if path is a mountpoint for fstype
func IsMountpoint(path string, fstype string) (bool, error) {
	mountsFile := "/proc/mounts"
	file, err := os.Open(mountsFile)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		currFstype := sline[2]

		if fstype == currFstype && mountpoint == path {
			return true, nil
		}
	}

	return false, nil
}

// SearchMountpoint finds the last mountpoint for the given fstype which
// includes the search string if the search string is empty the function will
// return the last found path
func SearchMountpoint(fstype string, search string) (string, error) {
	mountsFile := "/proc/mounts"
	file, err := os.Open(mountsFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	mp := ""
	scanner := bufio.NewScanner(file)
	for i := 1; scanner.Scan(); i++ {
		sline := strings.Split(scanner.Text(), " ")
		mountpoint := sline[1]
		currFstype := sline[2]

		if fstype == currFstype && strings.Contains(mountpoint, search) {
			mp = mountpoint
		}
	}
	return mp, nil
}
