package logger

import (
	"sync"

	"golang.org/x/exp/maps"
)

type logOrigin struct {
	File  string
	Line  int
	Level Level
	Msg   string
}

type logCounter struct {
	rwMutex sync.RWMutex
	data    map[logOrigin]uint32
}

func (lc *logCounter) update(lo logOrigin) {
	lc.rwMutex.Lock()
	defer lc.rwMutex.Unlock()

	lc.data[lo]++
}

func (lc *logCounter) Lookup(key logOrigin) (count uint32, found bool) {
	lc.rwMutex.RLock()
	defer lc.rwMutex.RUnlock()

	count, found = lc.data[key]
	return count, found
}

func (lc *logCounter) dump(flush bool) map[logOrigin]uint32 {
	if flush {
		lc.rwMutex.Lock()
		defer lc.rwMutex.Unlock()
	} else {
		lc.rwMutex.RLock()
		defer lc.rwMutex.RUnlock()
	}

	dump := make(map[logOrigin]uint32, len(lc.data))
	maps.Copy(dump, lc.data)

	if flush {
		maps.Clear(lc.data)
	}

	return dump
}

func (lc *logCounter) Dump() map[logOrigin]uint32 {
	return lc.dump(false)
}

func (lc *logCounter) Flush() map[logOrigin]uint32 {
	return lc.dump(true)
}

func newLogCounter() *logCounter {
	return &logCounter{
		rwMutex: sync.RWMutex{},
		data:    map[logOrigin]uint32{},
	}
}
