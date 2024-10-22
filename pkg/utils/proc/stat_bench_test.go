package proc

import (
	"os"
	"testing"

	"github.com/aquasecurity/tracee/pkg/utils/tests"
)

func createMockStatFile() (string, error) {
	dirPath := "/tmp/tracee-test"
	filePath, err := tests.GenerateTimestampFileName(dirPath, "stat")
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(dirPath, 0755)
	if err != nil {
		return "", err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content := "3529367 (Isolated Web Co) S 3437358 3433422 3433422 0 -1 4194560 " +
		"50679 0 0 0 566 643 0 0 20 0 29 0 46236871 2609160192 33222 " +
		"18446744073709551615 94165013317536 94165014109840 140730010890672 " +
		"0 0 0 0 16846850 1082134264 0 0 0 17 29 0 0 0 0 0 94165014122560 " +
		"94165014122664 94165887094784 140730010895394 140730010895699 " +
		"140730010895699 140730010898399 0\n"

	_, err = file.WriteString(content)
	if err != nil {
		return "", err
	}

	return filePath, nil
}

func Benchmark_newProcStat(b *testing.B) {
	filePath, err := createMockStatFile()
	if err != nil {
		os.Remove(filePath)
		b.Fatalf("Failed to create mock stat file: %v", err)
	}
	defer os.Remove(filePath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = newProcStat(filePath)
	}
}
