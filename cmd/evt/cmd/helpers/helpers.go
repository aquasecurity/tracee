package helpers

import (
	"fmt"
	"io"
	"path/filepath"
)

type PrefixWriter struct {
	Prefix []byte
	Writer io.Writer
}

// Write writes the given bytes with the prefix
func (pw *PrefixWriter) Write(p []byte) (int, error) {
	return pw.Writer.Write(append(pw.Prefix, p...))
}

const (
	MaxCommLen = 16
)

func GetFilterOutCommScope(cmd string) string {
	comm := filepath.Base(cmd)
	comm = comm[:min(len(comm), MaxCommLen-1)]
	return fmt.Sprintf("comm!=%s", comm)
}

func GetFilterInTreeScope(pid string) string {
	return fmt.Sprintf("tree=%s", pid)
}
