package proctree

import (
	"sync"
	"time"

	ch "github.com/aquasecurity/tracee/pkg/changelog"
)

// FileInfoFeed allows external packages to set/get multiple values of a task at once.
type FileInfoFeed struct {
	// Name      string
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
	path      *ch.Changelog[string] // file path
	dev       *ch.Changelog[int]    // device number of the file
	ctime     *ch.Changelog[int]    // creation time of the file
	inode     *ch.Changelog[int]    // inode number of the file
	inodeMode *ch.Changelog[int]    // inode mode of the file
	mutex     *sync.RWMutex
}

// NewFileInfo creates a new file.
func NewFileInfo(maxLogSize int) *FileInfo {
	return &FileInfo{
		path:      ch.NewChangelog[string](maxLogSize),
		dev:       ch.NewChangelog[int](maxLogSize),
		ctime:     ch.NewChangelog[int](maxLogSize),
		inode:     ch.NewChangelog[int](maxLogSize),
		inodeMode: ch.NewChangelog[int](maxLogSize),
		mutex:     &sync.RWMutex{},
	}
}

// NewFileInfoFeed creates a new file with values from the given feed.
func NewFileInfoFeed(maxLogSize int, feed FileInfoFeed) *FileInfo {
	new := NewFileInfo(maxLogSize)
	new.SetFeed(feed)
	return new
}

// Multiple values at once (using a feed structure)

// SetFeed sets the values of the file from a feed.
func (fi *FileInfo) SetFeed(feed FileInfoFeed) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.SetFeedAt(feed, time.Now())
}

// SetFeedAt sets the values of the file from a feed at the given time.
func (fi *FileInfo) SetFeedAt(feed FileInfoFeed, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.setFeedAt(feed, targetTime)
}

// Paths theoretically has no limit, but we do need to set a limit for the sake of
// managing memory more responsibly.
const MaxPathLen = 1024

func (fi *FileInfo) setFeedAt(feed FileInfoFeed, targetTime time.Time) {
	if feed.Path != "" {
		filePath := feed.Path
		if len(filePath) > MaxPathLen {
			// Take only the end of the path, as the specific file name and location are the most
			// important parts.
			filePath = filePath[len(filePath)-MaxPathLen:]
		}
		fi.path.Set(filePath, targetTime)
	}
	if feed.Dev >= 0 {
		fi.dev.Set(feed.Dev, targetTime)
	}
	if feed.Ctime >= 0 {
		fi.ctime.Set(feed.Ctime, targetTime)
	}
	if feed.Inode >= 0 {
		fi.inode.Set(feed.Inode, targetTime)
	}
	if feed.InodeMode >= 0 {
		fi.inodeMode.Set(feed.InodeMode, targetTime)
	}
}

// GetFeed returns the values of the file as a feed.
func (fi *FileInfo) GetFeed() FileInfoFeed {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.getFeedAt(time.Now())
}

// GetFeedAt returns the values of the file as a feed at the given time.
func (fi *FileInfo) GetFeedAt(targetTime time.Time) FileInfoFeed {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.getFeedAt(targetTime) // return values at the given time
}

func (fi *FileInfo) getFeedAt(targetTime time.Time) FileInfoFeed {
	return FileInfoFeed{
		Path:      fi.path.Get(targetTime),
		Dev:       fi.dev.Get(targetTime),
		Ctime:     fi.ctime.Get(targetTime),
		Inode:     fi.inode.Get(targetTime),
		InodeMode: fi.inodeMode.Get(targetTime),
	}
}

// Setters

// SetPath sets the path of the file.
func (fi *FileInfo) SetPath(path string) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.path.Set(path, time.Now())
}

// SetPathAt sets the path of the file at the given time.
func (fi *FileInfo) SetPathAt(path string, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.path.Set(path, targetTime)
}

// SetDev sets the device number of the file.
func (fi *FileInfo) SetDev(dev int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.dev.Set(dev, time.Now())
}

// SetDevAt sets the device number of the file at the given time.
func (fi *FileInfo) SetDevAt(dev int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.dev.Set(dev, targetTime)
}

// SetCtime sets the creation time of the file.
func (fi *FileInfo) SetCtime(ctime int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.ctime.Set(ctime, time.Now())
}

// SetCtimeAt sets the creation time of the file at the given time.
func (fi *FileInfo) SetCtimeAt(ctime int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.ctime.Set(ctime, targetTime)
}

// SetInode sets the inode number of the file.
func (fi *FileInfo) SetInode(inode int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.inode.Set(inode, time.Now())
}

// SetInodeAt sets the inode number of the file at the given time.
func (fi *FileInfo) SetInodeAt(inode int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.inode.Set(inode, targetTime)
}

// SetInodeMode sets the inode mode of the file.
func (fi *FileInfo) SetInodeMode(inodeMode int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.inodeMode.Set(inodeMode, time.Now())
}

// SetInodeModeAt sets the inode mode of the file at the given time.
func (fi *FileInfo) SetInodeModeAt(inodeMode int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()
	fi.inodeMode.Set(inodeMode, targetTime)
}

// Getters

// GetPath returns the path of the file.
func (fi *FileInfo) GetPath() string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.path.Get(time.Now())
}

// GetPathAt returns the path of the file at the given time.
func (fi *FileInfo) GetPathAt(targetTime time.Time) string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.path.Get(targetTime)
}

// GetDev returns the device number of the file.
func (fi *FileInfo) GetDev() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.dev.Get(time.Now())
}

// GetDevAt returns the device number of the file at the given time.
func (fi *FileInfo) GetDevAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.dev.Get(targetTime)
}

// GetCtime returns the creation time of the file.
func (fi *FileInfo) GetCtime() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.ctime.Get(time.Now())
}

// GetCtimeAt returns the creation time of the file at the given time.
func (fi *FileInfo) GetCtimeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.ctime.Get(targetTime)
}

// GetInode returns the inode number of the file.
func (fi *FileInfo) GetInode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.inode.Get(time.Now())
}

// GetInodeAt returns the inode number of the file at the given time.
func (fi *FileInfo) GetInodeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.inode.Get(targetTime)
}

// GetInodeMode returns the inode mode of the file.
func (fi *FileInfo) GetInodeMode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.inodeMode.Get(time.Now())
}

// GetInodeModeAt returns the inode mode of the file at the given time.
func (fi *FileInfo) GetInodeModeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()
	return fi.inodeMode.Get(targetTime)
}
