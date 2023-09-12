package proctree

import (
	"sync"
)

// FileInfoFeed allows external packages to set/get multiple values of a task at once.
type FileInfoFeed struct {
	Name      string
	Path      string
	Dev       int
	Ctime     int
	Inode     int
	InodeMode int
}

//
// File Info
//

// FileInfo represents a file.
type FileInfo struct {
	name      string // file name
	path      string // file path
	dev       int    // device number of the file
	ctime     int    // creation time of the file
	inode     int    // inode number of the file
	inodeMode int    // inode mode of the file
	mutex     *sync.RWMutex
}

// NewFileInfo creates a new file.
func NewFileInfo() *FileInfo {
	return &FileInfo{
		mutex: &sync.RWMutex{},
	}
}

// NewFileInfoFeed creates a new file with values from the given feed.
func NewFileInfoFeed(feed FileInfoFeed) *FileInfo {
	new := NewFileInfo()
	new.SetFeed(feed)
	return new
}

// Multiple values at once (using a feed structure)

// SetFeed sets the values of the file from the given feed.
func (fi *FileInfo) SetFeed(feed FileInfoFeed) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	if feed.Name != "" && fi.name != feed.Name {
		fi.name = feed.Name
	}
	if feed.Path != "" && fi.path != feed.Path {
		fi.path = feed.Path
	}
	if feed.Dev >= 0 && fi.dev != feed.Dev {
		fi.dev = feed.Dev
	}
	if feed.Ctime >= 0 && fi.ctime != feed.Ctime {
		fi.ctime = feed.Ctime
	}
	if feed.Inode >= 0 && fi.inode != feed.Inode {
		fi.inode = feed.Inode
	}
	if feed.InodeMode >= 0 && fi.inodeMode != feed.InodeMode {
		fi.inodeMode = feed.InodeMode
	}
}

// GetValue returns the values of the file as a feed.
func (fi *FileInfo) GetFeed() FileInfoFeed {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return FileInfoFeed{
		Name:      fi.name,
		Path:      fi.path,
		Dev:       fi.dev,
		Ctime:     fi.ctime,
		Inode:     fi.inode,
		InodeMode: fi.inodeMode,
	}
}

// Setters

// SetName sets the name of the file.
func (fi *FileInfo) SetName(name string) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.name = name
}

// SetPath sets the path of the file.
func (fi *FileInfo) SetPath(path string) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.path = path
}

// SetDev sets the dev of the file.
func (fi *FileInfo) SetDev(dev int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.dev = dev
}

// SetCtime sets the ctime of the file.
func (fi *FileInfo) SetCtime(ctime int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.ctime = ctime
}

// SetInode sets the inode of the file.
func (fi *FileInfo) SetInode(inode int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.inode = inode
}

// SetInodeMode sets the inode mode of the file.
func (fi *FileInfo) SetInodeMode(inodeMode int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.inodeMode = inodeMode
}

// Getters

// GetName returns the name of the file.
func (fi *FileInfo) GetName() string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.name
}

// GetPath returns the path of the file.
func (fi *FileInfo) GetPath() string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.path
}

// GetDev returns the dev of the file.
func (fi *FileInfo) GetDev() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.dev
}

// GetCtime returns the ctime of the file.
func (fi *FileInfo) GetCtime() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.ctime
}

// GetInode returns the inode of the file.
func (fi *FileInfo) GetInode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.inode
}

// GetInodeMode returns the inode mode of the file.
func (fi *FileInfo) GetInodeMode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.inodeMode
}
