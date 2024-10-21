package tests

import (
	"fmt"
	"path/filepath"
	"time"
)

func GenerateTimestampFileName(dir string, filenamePrefix string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	fullPath := filepath.Join(dir, fmt.Sprintf("%s_%s", filenamePrefix, timestamp))

	return fullPath, nil
}
