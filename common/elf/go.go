package elf

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	_ "unsafe" // required for go:linkname directive
)

var ErrNotGoBinary = errors.New("not a go binary")

type GoVersion struct {
	Major, Minor, Patch int
}

var goVersionRegex = regexp.MustCompile(`^go(\d+)\.(\d+)(?:\.(\d+))?(?:\s.*)?$`)

//go:linkname errNotGoExe debug/buildinfo.errNotGoExe
var errNotGoExe error

func (ea *ElfAnalyzer) GetGoVersion() (*GoVersion, error) {
	// Already found version
	if ea.goVersion != nil {
		return ea.goVersion, nil
	}

	// Already tried finding version but failed
	if ea.goVersionError != nil {
		return nil, ea.goVersionError
	}

	buildInfo, err := buildinfo.ReadFile(ea.filePath)
	if err != nil {
		if errors.Is(err, errNotGoExe) {
			// Use our own error type
			err = ErrNotGoBinary
		}

		ea.goVersionError = err
		return nil, err
	}

	version, err := parseGoVersion(buildInfo.GoVersion)
	if err != nil {
		ea.goVersionError = err
		return nil, err
	}

	ea.goVersion = version
	return version, nil
}

// parseGoVersion parses a Go version string and returns a GoVersion struct
func parseGoVersion(versionStr string) (*GoVersion, error) {
	version := &GoVersion{}

	matches := goVersionRegex.FindStringSubmatch(versionStr)
	if matches == nil {
		return nil, fmt.Errorf("error parsing go version string \"%s\"", versionStr)
	}

	var err error
	version.Major, err = strconv.Atoi(matches[1])
	if err != nil {
		return nil, fmt.Errorf("error parsing go version string \"%s\": invalid major version", versionStr)
	}

	version.Minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return nil, fmt.Errorf("error parsing go version string \"%s\": invalid minor version", versionStr)
	}

	if matches[3] != "" {
		version.Patch, err = strconv.Atoi(matches[3])
		if err != nil {
			return nil, fmt.Errorf("error parsing go version string \"%s\": invalid patch version", versionStr)
		}
	}

	return version, nil
}
