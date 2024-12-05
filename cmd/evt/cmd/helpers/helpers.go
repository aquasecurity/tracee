package helpers

import (
	"fmt"
	"io"
	"path/filepath"
)

func GetFilterOutCommScope(cmd string) string {
	comm := filepath.Base(cmd)
	comm = comm[:min(len(comm), 15)]
	return fmt.Sprintf("comm!=%s", comm)
}

type PrefixWriter struct {
	Prefix []byte
	Writer io.Writer
}

// Write writes the given bytes with the prefix
func (pw *PrefixWriter) Write(p []byte) (int, error) {
	return pw.Writer.Write(append(pw.Prefix, p...))
}
