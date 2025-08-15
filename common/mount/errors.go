package mount

import (
	"fmt"
)

func UnmountedDirNotEmpty(dir string) error {
	return fmt.Errorf("unmounted directory %v isn't empty", dir)
}

func CouldNotOpenFile(path string, err error) error {
	return fmt.Errorf("could not open %s: %w", path, err)
}
