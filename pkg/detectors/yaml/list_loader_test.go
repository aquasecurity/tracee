package yaml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateListName(t *testing.T) {
	testCases := []struct {
		name      string
		listName  string
		expectErr bool
	}{
		{"valid uppercase", "SHELL_BINARIES", false},
		{"valid single word", "SHELLS", false},
		{"valid with numbers", "LIST_123", false},
		{"invalid lowercase", "shell_binaries", true},
		{"invalid mixed case", "Shell_Binaries", true},
		{"invalid starts with number", "123_LIST", true},
		{"invalid starts with underscore", "_LIST", true},
		{"invalid empty", "", true},
		{"invalid space", "SHELL BINARIES", true},
		{"invalid dash", "SHELL-BINARIES", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateListName(tc.listName)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
