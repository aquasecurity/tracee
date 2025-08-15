package tests

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func GenerateTimestampFileName(dir string, filenamePrefix string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	fullPath := filepath.Join(dir, fmt.Sprintf("%s_%s", filenamePrefix, timestamp))

	return fullPath, nil
}

// PrintStructSizes prints the size of a struct and the size of its fields
func PrintStructSizes(tb testing.TB, w io.Writer, structure interface{}) {
	tb.Helper()

	typ := reflect.TypeOf(structure)

	// if the type is a pointer to a struct, dereference it
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		fmt.Fprintf(w, "Type %s is not a struct\n", typ.Kind())
		return
	}

	totalSize := typ.Size()
	expectedSize := uintptr(0)
	fieldsInfo := "["

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldSize := field.Type.Size()
		fieldOffset := field.Offset
		fieldsInfo += fmt.Sprintf(
			"%s:%s %d bytes (offset=%d), ",
			field.Name, field.Type.String(), fieldSize, fieldOffset,
		)
		expectedSize += fieldSize
	}

	padding := totalSize - expectedSize
	paddingInfo := ""
	if padding > 0 {
		paddingInfo = "(has padding)"
	}

	// remove trailing comma and space
	if len(fieldsInfo) > 2 {
		fieldsInfo = fieldsInfo[:len(fieldsInfo)-2]
	}
	fieldsInfo += "]"

	fmt.Fprintf(w, "%s: %d bytes %s %s\n", typ.Name(), totalSize, fieldsInfo, paddingInfo)
}

func CreateTempFile(tb testing.TB, content string) *os.File {
	tb.Helper()

	file, err := os.CreateTemp("", "test_temp_file_*.txt")
	if err != nil {
		tb.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := file.WriteString(content); err != nil {
		tb.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := file.Close(); err != nil {
		tb.Fatalf("Failed to close temp file: %v", err)
	}

	return file
}
