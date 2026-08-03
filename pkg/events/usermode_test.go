package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseNamespaceInode pins the /proc/*/ns symlink-target parse: real
// targets must yield their inode, malformed ones must error (never 0-as-value,
// which downstream consumers treat as authoritative).
func TestParseNamespaceInode(t *testing.T) {
	t.Parallel()

	valid := map[string]uint32{
		"mnt:[4026531840]":    4026531840,
		"pid:[4026531836]":    4026531836,
		"cgroup:[4026531835]": 4026531835,
		"time:[4026531834]":   4026531834,
	}
	for link, want := range valid {
		got, err := parseNamespaceInode(link)
		assert.NoError(t, err, link)
		assert.Equal(t, want, got, link)
	}

	malformed := []string{
		"",
		"garbage",
		"mnt:[]",
		"mnt:[0]",
		"mnt:4026531840",
		"mnt:[abc]",
	}
	for _, link := range malformed {
		_, err := parseNamespaceInode(link)
		assert.Error(t, err, link)
	}
}
