package filehash

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/config"
	"github.com/aquasecurity/tracee/pkg/errfmt"
)

const hostDigest = "host"

type Key struct {
	filePath string
	mountNS  int

	device      uint32
	inode       uint64
	ctime       int64
	imageDigest string
}

// NewKey creates a base key for usage with the file hash cache.
// It requires a filepath and mountns for the key as base information.
// Further information must be added through options.
func NewKey(filepath string, mountNS int, opts ...func(*Key)) Key {
	k := Key{filePath: filepath, mountNS: mountNS}
	for _, o := range opts {
		o(&k)
	}
	return k
}

// WithDevice adds a device to the key.
func WithDevice(device uint32) func(*Key) {
	return func(k *Key) {
		k.device = device
	}
}

// WithInode adds inode information to the key.
func WithInode(ino uint64, ctime int64) func(*Key) {
	return func(k *Key) {
		k.inode = ino
		k.ctime = ctime
	}
}

// With digest associates the key to a specific container digest, or to host.
func WithDigest(digest string) func(*Key) {
	return func(k *Key) {
		if digest == "" {
			digest = hostDigest
		}
		k.imageDigest = digest
	}
}

// Pathname returns the file's pathname associated to the key.
func (k *Key) Pathname() string {
	return k.filePath
}

// Pathname returns the file's mount namespace associated to the key.
func (k *Key) MountNS() int {
	return k.mountNS
}

// DeviceKey returns a string key for the file's device and inode.
// Format is "device:ctime:inode".
func (k *Key) DeviceKey() string {
	return fmt.Sprintf("%d:%s", k.device, k.InodeKey())
}

// DigestKey returns a string key based on the file container origin(digest or host),
// and it's inode key.
// Format is "digest:ctime:inode".
func (k *Key) DigestKey() string {
	if k.imageDigest == "" {
		return ""
	}

	return fmt.Sprintf("%s:%s", k.imageDigest, k.InodeKey())
}

// InodeKey returns a string key based on the file inode
// Format is "ctime:inode"
func (k *Key) InodeKey() string {
	return fmt.Sprintf("%d:%d", k.ctime, k.inode)
}

// get key with relation to CalcHashesOption
// Note: this may still return empty according to values supplied to the key
func getKeyByExecHashMode(k *Key, mode config.CalcHashesOption) (string, error) {
	switch mode {
	case config.CalcHashesInode:
		return k.InodeKey(), nil
	case config.CalcHashesDevInode:
		return k.DeviceKey(), nil
	case config.CalcHashesDigestInode:
		return k.DigestKey(), nil // can be empty if container digest is not available
	}

	return "", errfmt.Errorf("unknown calc hash option type")
}
