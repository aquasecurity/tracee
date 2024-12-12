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

const (
	// string members
	fileInfoPath changelog.MemberKind = iota
)

const (
	// int members
	fileInfoDev changelog.MemberKind = iota
	fileInfoCtime
	fileInfoInode
	fileInfoInodeMode
)

var (
	// fileInfoMutableStringsFlags is a slice with metadata about the mutable string members of a FileInfo.
	fileInfoMutableStringsFlags = []changelog.MaxEntries{
		fileInfoPath: 3, // file path
	}

	// fileInfoMutableIntsFlags is a slice with metadata about the mutable int members of a FileInfo.
	fileInfoMutableIntsFlags = []changelog.MaxEntries{
		fileInfoDev:       3, // device number of the file
		fileInfoCtime:     3, // creation time of the file
		fileInfoInode:     3, // inode number of the file
		fileInfoInodeMode: 3, // inode mode of the file
	}
)

// FileInfo represents a file.
type FileInfo struct {
	mutableStrings *changelog.ChangelogKind[string]
	mutableInts    *changelog.ChangelogKind[int]
	mutex          *sync.RWMutex
}

// NewFileInfo creates a new file.
func NewFileInfo() *FileInfo {
	return &FileInfo{
		mutableStrings: changelog.NewChangelogKind[string](fileInfoMutableStringsFlags),
		mutableInts:    changelog.NewChangelogKind[int](fileInfoMutableIntsFlags),
		mutex:          &sync.RWMutex{},
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

// Single values

// SetPath sets the path of the file.
func (fi *FileInfo) SetPath(path string) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setPathAt(path, time.Now())
}

// SetPathAt sets the path of the file at the given time.
func (fi *FileInfo) SetPathAt(path string, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setPathAt(path, targetTime)
}

// SetDev sets the device number of the file.
func (fi *FileInfo) SetDev(dev int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setDevAt(dev, time.Now())
}

// SetDevAt sets the device number of the file at the given time.
func (fi *FileInfo) SetDevAt(dev int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setDevAt(dev, targetTime)
}

// SetCtime sets the creation time of the file.
func (fi *FileInfo) SetCtime(ctime int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setCtimeAt(ctime, time.Now())
}

// SetCtimeAt sets the creation time of the file at the given time.
func (fi *FileInfo) SetCtimeAt(ctime int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setCtimeAt(ctime, targetTime)
}

// SetInode sets the inode number of the file.
func (fi *FileInfo) SetInode(inode int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setInodeAt(inode, time.Now())
}

// SetInodeAt sets the inode number of the file at the given time.
func (fi *FileInfo) SetInodeAt(inode int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setInodeAt(inode, targetTime)
}

// SetInodeMode sets the inode mode of the file.
func (fi *FileInfo) SetInodeMode(inodeMode int) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setInodeAt(inodeMode, time.Now())
}

// SetInodeModeAt sets the inode mode of the file at the given time.
func (fi *FileInfo) SetInodeModeAt(inodeMode int, targetTime time.Time) {
	fi.mutex.Lock()
	defer fi.mutex.Unlock()

	fi.setInodeModeAt(inodeMode, targetTime)
}

// private setters

func (fi *FileInfo) setFeed(feed FileInfoFeed) {
	fi.setFeedAt(feed, time.Now())
}

// Paths theoretically has no limit, but we do need to set a limit for the sake of
// managing memory more responsibly.
const MaxPathLen = 1024

func (fi *FileInfo) setFeedAt(feed FileInfoFeed, targetTime time.Time) {
	if feed.Path != "" {
		filePath := feed.Path
		if len(filePath) > MaxPathLen {
			// Take only the end of the path, as the specific file name and location
			// are the most important parts. Cloning prevents memory retention.
			filePath = strings.Clone(filePath[len(filePath)-MaxPathLen:])
		}
		fi.setPathAt(filePath, targetTime)
	}

	if feed.Dev >= 0 {
		fi.setDevAt(feed.Dev, targetTime)
	}
	if feed.Ctime >= 0 {
		fi.setCtimeAt(feed.Ctime, targetTime)
	}
	if feed.Inode >= 0 {
		fi.setInodeAt(feed.Inode, targetTime)
	}
	if feed.InodeMode >= 0 {
		fi.setInodeModeAt(feed.InodeMode, targetTime)
	}
}

func (fi *FileInfo) setPathAt(path string, targetTime time.Time) {
	fi.mutableStrings.Set(fileInfoPath, path, targetTime)
}

func (fi *FileInfo) setDevAt(dev int, targetTime time.Time) {
	fi.mutableInts.Set(fileInfoDev, dev, targetTime)
}

func (fi *FileInfo) setCtimeAt(ctime int, targetTime time.Time) {
	fi.mutableInts.Set(fileInfoCtime, ctime, targetTime)
}

func (fi *FileInfo) setInodeAt(inode int, targetTime time.Time) {
	fi.mutableInts.Set(fileInfoInode, inode, targetTime)
}

func (fi *FileInfo) setInodeModeAt(inodeMode int, targetTime time.Time) {
	fi.mutableInts.Set(fileInfoInodeMode, inodeMode, targetTime)
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

	return fi.getPath()
}

// GetPathAt returns the path of the file at the given time.
func (fi *FileInfo) GetPathAt(targetTime time.Time) string {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getPathAt(targetTime)
}

// GetDev returns the device number of the file.
func (fi *FileInfo) GetDev() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getDev()
}

// GetDevAt returns the device number of the file at the given time.
func (fi *FileInfo) GetDevAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getDevAt(targetTime)
}

// GetCtime returns the creation time of the file.
func (fi *FileInfo) GetCtime() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getCtime()
}

// GetCtimeAt returns the creation time of the file at the given time.
func (fi *FileInfo) GetCtimeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getCtimeAt(targetTime)
}

// GetInode returns the inode number of the file.
func (fi *FileInfo) GetInode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getInode()
}

// GetInodeAt returns the inode number of the file at the given time.
func (fi *FileInfo) GetInodeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getInodeAt(targetTime)
}

// GetInodeMode returns the inode mode of the file.
func (fi *FileInfo) GetInodeMode() int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getInodeMode()
}

// GetInodeModeAt returns the inode mode of the file at the given time.
func (fi *FileInfo) GetInodeModeAt(targetTime time.Time) int {
	fi.mutex.RLock()
	defer fi.mutex.RUnlock()

	return fi.getInodeModeAt(targetTime)
}

// private getters

func (fi *FileInfo) getFeed() FileInfoFeed {
	return FileInfoFeed{
		Path:      fi.getPath(),
		Dev:       fi.getDev(),
		Ctime:     fi.getCtime(),
		Inode:     fi.getInode(),
		InodeMode: fi.getInodeMode(),
	}
}

func (fi *FileInfo) getFeedAt(targetTime time.Time) FileInfoFeed {
	return FileInfoFeed{
		Path:      fi.getPathAt(targetTime),
		Dev:       fi.getDevAt(targetTime),
		Ctime:     fi.getCtimeAt(targetTime),
		Inode:     fi.getInodeAt(targetTime),
		InodeMode: fi.getInodeModeAt(targetTime),
	}
}

func (fi *FileInfo) getPath() string {
	return fi.mutableStrings.GetCurrent(fileInfoPath)
}

func (fi *FileInfo) getPathAt(targetTime time.Time) string {
	return fi.mutableStrings.Get(fileInfoPath, targetTime)
}

func (fi *FileInfo) getDev() int {
	return fi.mutableInts.GetCurrent(fileInfoDev)
}

func (fi *FileInfo) getDevAt(targetTime time.Time) int {
	return fi.mutableInts.Get(fileInfoDev, targetTime)
}

func (fi *FileInfo) getCtime() int {
	return fi.mutableInts.GetCurrent(fileInfoCtime)
}

func (fi *FileInfo) getCtimeAt(targetTime time.Time) int {
	return fi.mutableInts.Get(fileInfoCtime, targetTime)
}

func (fi *FileInfo) getInode() int {
	return fi.mutableInts.GetCurrent(fileInfoInode)
}

func (fi *FileInfo) getInodeAt(targetTime time.Time) int {
	return fi.mutableInts.Get(fileInfoInode, targetTime)
}

func (fi *FileInfo) getInodeMode() int {
	return fi.mutableInts.GetCurrent(fileInfoInodeMode)
}

func (fi *FileInfo) getInodeModeAt(targetTime time.Time) int {
	return fi.mutableInts.Get(fileInfoInodeMode, targetTime)
}
