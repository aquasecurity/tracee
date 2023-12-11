package filehash_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/filehash"
)

func computeFileHashOld(file *os.File) (string, error) {
	h := sha256.New()

	_, err := io.Copy(h, file)
	if err != nil {
		return "", errfmt.WrapError(err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func TestCurrentHashCompatibility(t *testing.T) {
	files := []string{
		"/usr/bin/uname",
		"/usr/bin/date",
	}

	for _, filePath := range files {

		file, err := os.Open(filePath)
		if err != nil {
			t.Fatal(err)
		}

		h1, err := filehash.ComputeFileHash(file)
		require.NoError(t, err)
		_, err = file.Seek(0, 0)
		require.NoError(t, err)
		h2, err := computeFileHashOld(file)
		require.NoError(t, err)
		err = file.Close()
		require.NoError(t, err)
		assert.Equal(t, h1, h2)
	}
}
