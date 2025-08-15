package proc

import (
	"io"
	"os"
)

// ReadFile reads the content of a file and returns it as a byte slice.
// This function is specifically optimized for reading small files in the /proc directory,
// where the file size reported by the stat syscall is often 0.
// It reads the file in chunks, dynamically growing the buffer as needed to ensure all
// content is retrieved efficiently.
func ReadFile(filePath string, initialBufferSize int) ([]byte, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	data := make([]byte, 0, initialBufferSize)

	// read file in chunks
	for {
		n, err := file.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}

			return data, err
		}

		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
	}
}
