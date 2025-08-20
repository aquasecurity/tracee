//go:build static

package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"
)

// MapType uses the same type alias as the real implementation for compatibility
type MapType = bpf.MapType

// BPF Map Type constants with unique values for static analysis
// These values don't need to match the real libbpf constants since
// they're only used during static analysis and won't cause duplicate key errors
const (
	HashMapType                MapType = 1
	ArrayMapType               MapType = 2
	ProgArrayMapType           MapType = 3
	PerfEventArrayMapType      MapType = 4
	PercpuHashMapType          MapType = 5
	PercpuArrayMapType         MapType = 6
	StackTraceMapType          MapType = 7
	CgroupArrayMapType         MapType = 8
	LruHashMapType             MapType = 9
	LruPercpuHashMapType       MapType = 10
	LpmTrieMapType             MapType = 11
	ArrayOfMapsMapType         MapType = 12
	HashOfMapsMapType          MapType = 13
	DevmapMapType              MapType = 14
	SockmapMapType             MapType = 15
	CpumapMapType              MapType = 16
	XskmapMapType              MapType = 17
	SockhashMapType            MapType = 18
	CgroupStorageMapType       MapType = 19
	ReuseportSockarrayMapType  MapType = 20
	PercpuCgroupStorageMapType MapType = 21
	QueueMapType               MapType = 22
	StackMapType               MapType = 23
	SkStorageMapType           MapType = 24
	DevmapHashMapType          MapType = 25
	StructOpsMapType           MapType = 26
	RingbufMapType             MapType = 27
	InodeStorageMapType        MapType = 28
	TaskStorageMapType         MapType = 29
	BloomFilterMapType         MapType = 30
	UserRingbufMapType         MapType = 31
	CgrpStorageMapType         MapType = 32
	ArenaMapType               MapType = 33
)
