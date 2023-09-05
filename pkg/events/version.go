package events

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// 1. Major field is bumped whenever some data the event used to have was changed
// e.g. a field was renamed or removed
// 2. Minor field is bumped whenever a non breaking change occurs
// e.g. a new field was added to the event
// 3. Patch field is bumped whenever something is changed in the way the event works internally
// e.g. some bug was fixed in the code
type Version struct {
	major uint64
	minor uint64
	patch uint64
}

// NewVersion creates a new version
func NewVersion(major, minor, patch uint64) Version {
	return Version{
		major,
		minor,
		patch,
	}
}

// NewVersionFromString creates a new version from a string
func NewVersionFromString(v string) (Version, error) {
	version, err := semver.StrictNewVersion(v)
	if err != nil {
		return Version{}, err
	}

	return Version{
		major: version.Major(),
		minor: version.Minor(),
		patch: version.Patch(),
	}, nil
}

// Major returns the major version of the event
func (v Version) Major() uint64 {
	return v.major
}

// Minor returns the minor version of the event
func (v Version) Minor() uint64 {
	return v.minor
}

// Patch returns the patch version of the event
func (v Version) Patch() uint64 {
	return v.patch
}

// String returns the string representation of the event version
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}
