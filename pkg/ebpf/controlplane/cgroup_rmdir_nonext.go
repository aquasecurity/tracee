//go:build !extended

package controlplane

// cgroupRmdirExtended is a stub for non-extended builds.
// In extended builds, this is replaced.
func cgroupRmdirExtended(_ uint64) {}
