package proctree

import (
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/pkg/changelog"
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
	feed  *changelog.Changelog[FileInfoFeed]
	mutex *sync.RWMutex
}

// NewFileInfo creates a new file.
func NewFileInfo() *FileInfo {
	return &FileInfo{
		feed:  changelog.NewChangelog[FileInfoFeed](3),
		mutex: &sync.RWMutex{},
	}
}

// NewFileInfoFeed creates a new file with values from the given feed.
func NewFileInfoFeed(feed FileInfoFeed) *FileInfo {
	new := NewFileInfo()
	new.setFeed(feed)

	return new
}

//
// Setters
//

// Multiple values at once (using a feed structure)

// SetFeed sets the values of the file from a feed at the current time.
func (fi *FileInfo) SetFeed(feed FileInfoFeed) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setFeed(feed)
}

// SetFeedAt sets the values of the file from a feed at the given time.
func (fi *FileInfo) SetFeedAt(feed FileInfoFeed, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setFeedAt(feed, targetTime)
}

// private setters

func (fi *FileInfo) setFeed(feed FileInfoFeed) {
	fi.setFeedAt(feed, time.Now())
}

// Paths theoretically has no limit, but we do need to set a limit for the sake of
// managing memory more responsibly.
const MaxPathLen = 1024

func (fi *FileInfo) setFeedAt(feed FileInfoFeed, targetTime time.Time) {
	if len(feed.Path) > MaxPathLen {
		filePath := feed.Path
		if len(filePath) > MaxPathLen {
			// Take only the end of the path, as the specific file name and location
			// are the most important parts. Cloning prevents memory retention.
			filePath = strings.Clone(filePath[len(filePath)-MaxPathLen:])
		}
		feed.Path = filePath
	}

	fi.feed.Set(feed, targetTime)
}

//
// Getters
//

// Multiple values at once (getting a feed structure)

// GetFeed returns the values of the file as a feed.
func (fi *FileInfo) GetFeed() FileInfoFeed {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getFeed()
}

// GetFeedAt returns the values of the file as a feed at the given time.
func (fi *FileInfo) GetFeedAt(targetTime time.Time) FileInfoFeed {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getFeedAt(targetTime)
}

// Single values

// GetPath returns the path of the file.
func (fi *FileInfo) GetPath() string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.GetCurrent().Path
}

// GetPathAt returns the path of the file at the given time.
func (fi *FileInfo) GetPathAt(targetTime time.Time) string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.Get(targetTime).Path
}

// GetDev returns the device number of the file.
func (fi *FileInfo) GetDev() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.GetCurrent().Dev
}

// GetDevAt returns the device number of the file at the given time.
func (fi *FileInfo) GetDevAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.Get(targetTime).Dev
}

// GetCtime returns the creation time of the file.
func (fi *FileInfo) GetCtime() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.GetCurrent().Ctime
}

// GetCtimeAt returns the creation time of the file at the given time.
func (fi *FileInfo) GetCtimeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.Get(targetTime).Ctime
}

// GetInode returns the inode number of the file.
func (fi *FileInfo) GetInode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.GetCurrent().Inode
}

// GetInodeAt returns the inode number of the file at the given time.
func (fi *FileInfo) GetInodeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.Get(targetTime).Inode
}

// GetInodeMode returns the inode mode of the file.
func (fi *FileInfo) GetInodeMode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.GetCurrent().InodeMode
}

// GetInodeModeAt returns the inode mode of the file at the given time.
func (fi *FileInfo) GetInodeModeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.feed.Get(targetTime).InodeMode
}

// private getters

func (fi *FileInfo) getFeed() FileInfoFeed {
	return fi.feed.GetCurrent()
}

func (fi *FileInfo) getFeedAt(targetTime time.Time) FileInfoFeed {
	return fi.feed.Get(targetTime)
}
