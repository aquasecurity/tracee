package filehash

import (
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/logger"
)

var onceHashCapsAdd sync.Once // capabilities for exec hash enabled only once

type hashInfo struct {
	lastCtime int64
	hash      string
}

type pathResolver interface {
	GetHostAbsPath(absolutePath string, mountNS int) (string, error)
}

type Cache struct {
	execHashMode config.CalcHashesOption
	hashes       *lru.Cache[string, hashInfo]
	resolver     pathResolver
}

// NewCache creates a new cache for storing sha256 hashes with associated files.
// In order to meet multiple performance and correctness needs, the cache can operate in multiple modes.
//
//   - inode: recalculates the file hash if the inode's creation time (ctime) differs. The option is performant, but not necessarily correct.
//   - dev-inode: generally offers better performance compared to the inode option, as it bypasses the need
//     for recalculation by associating the creation time (ctime) with the device (dev) and inode pair. It's recommended if correctnes
//     is preferred over performance without container enrichment.
//   - digest-inode: is the most efficient, as it keys the hash to a pair consisting of the container image digest and inode.
//     This approach, however, necessitates container enrichment.
func NewCache(mode config.CalcHashesOption, resolver pathResolver) (*Cache, error) {
	hashes, err := lru.New[string, hashInfo](1024)
	if err != nil {
		return nil, fmt.Errorf("failed to create exechash cache: %v", err)
	}
	return &Cache{
		execHashMode: mode,
		hashes:       hashes,
		resolver:     resolver,
	}, nil
}

// Get returns a hash from the cache. It attempts to retrieve info from the key based on the mode initially given to the cache.
func (c *Cache) Get(k *Key) (string, error) {
	onceHashCapsAdd.Do(
		func() {
			logger.Infow("enabled cap.SYS_PTRACE")
			err := capabilities.GetInstance().BaseRingAdd(cap.SYS_PTRACE)
			if err != nil {
				logger.Errorw("error adding cap.SYS_PTRACE to base ring", "error", err)
			}
		},
	)

	key, err := getKeyByExecHashMode(k, c.execHashMode)
	if err != nil {
		return "", err
	}

	if key == "" {
		return "", fmt.Errorf("empty key given")
	}

	var fileHash string
	hashInfoObj, ok := c.hashes.Get(key)
	if ok && hashInfoObj.lastCtime == k.ctime {
		fileHash = hashInfoObj.hash
	} else {
		sourceFilePath, err := c.resolver.GetHostAbsPath(k.filePath, k.mountNS)
		if err != nil {
			return "", err
		}

		hash, err := ComputeFileHashAtPath(sourceFilePath)
		if err == nil {
			hashInfoObj = hashInfo{k.ctime, hash}
			c.hashes.Add(key, hashInfoObj)
			fileHash = hash
		}
	}

	return fileHash, nil
}
