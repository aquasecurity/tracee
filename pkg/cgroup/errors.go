package cgroup

import (
	"fmt"
)

type VersionNotSupported struct{}

func (c *VersionNotSupported) Error() string {
	return "unsupported cgroup version"
}

func NoCgroupSupport() error {
	return fmt.Errorf("could not find cgroup support")
}

func CouldNotFindOrMountDefaultCgroup(ver CgroupVersion) error {
	return fmt.Errorf("could not find/mount default %v support", ver.String())
}

func ErrorParsingFile(file string, err error) error {
	return fmt.Errorf("error parsing %s: %w", file, err)
}

func CouldNotOpenFile(file string, err error) error {
	return fmt.Errorf("could not open %s: %w", file, err)
}
