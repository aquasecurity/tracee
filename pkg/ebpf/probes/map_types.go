//go:build (core || ebpf) && !static

package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"
)

// MapType is an alias for libbpf MapType used for BPF map type identification
type MapType = bpf.MapType

// BPF Map Type constants mapped to their libbpf equivalents
const (
	HashMapType                MapType = bpf.MapTypeHash
	ArrayMapType               MapType = bpf.MapTypeArray
	ProgArrayMapType           MapType = bpf.MapTypeProgArray
	PerfEventArrayMapType      MapType = bpf.MapTypePerfEventArray
	PercpuHashMapType          MapType = bpf.MapTypePerCPUHash
	PercpuArrayMapType         MapType = bpf.MapTypePerCPUArray
	StackTraceMapType          MapType = bpf.MapTypeStackTrace
	CgroupArrayMapType         MapType = bpf.MapTypeCgroupArray
	LruHashMapType             MapType = bpf.MapTypeLRUHash
	LruPercpuHashMapType       MapType = bpf.MapTypeLRUPerCPUHash
	LpmTrieMapType             MapType = bpf.MapTypeLPMTrie
	ArrayOfMapsMapType         MapType = bpf.MapTypeArrayOfMaps
	HashOfMapsMapType          MapType = bpf.MapTypeHashOfMaps
	DevmapMapType              MapType = bpf.MapTypeDevMap
	SockmapMapType             MapType = bpf.MapTypeSockMap
	CpumapMapType              MapType = bpf.MapTypeCPUMap
	XskmapMapType              MapType = bpf.MapTypeXSKMap
	SockhashMapType            MapType = bpf.MapTypeSockHash
	CgroupStorageMapType       MapType = bpf.MapTypeCgroupStorage
	ReuseportSockarrayMapType  MapType = bpf.MapTypeReusePortSockArray
	PercpuCgroupStorageMapType MapType = bpf.MapTypePerCPUCgroupStorage
	QueueMapType               MapType = bpf.MapTypeQueue
	StackMapType               MapType = bpf.MapTypeStack
	SkStorageMapType           MapType = bpf.MapTypeSKStorage
	DevmapHashMapType          MapType = bpf.MapTypeDevmapHash
	StructOpsMapType           MapType = bpf.MapTypeStructOps
	RingbufMapType             MapType = bpf.MapTypeRingbuf
	InodeStorageMapType        MapType = bpf.MapTypeInodeStorage
	TaskStorageMapType         MapType = bpf.MapTypeTaskStorage
	BloomFilterMapType         MapType = bpf.MapTypeBloomFilter
	UserRingbufMapType         MapType = bpf.MapTypeUserRingbuf
	CgrpStorageMapType         MapType = bpf.MapTypeCgrpStorage
	ArenaMapType               MapType = bpf.MapTypeArena
)
