package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz

#include <bpf.h>
#include <libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include <asm-generic/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <string.h>
#include <unistd.h>

extern void perfCallback(void *ctx, int cpu, void *data, __u32 size);
extern void perfLostCallback(void *ctx, int cpu, __u64 cnt);

int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level != LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, format, args);
}

void set_print_fn() {
	libbpf_set_print(libbpf_print_fn);
}

struct perf_buffer * init_perf_buf(int map_fd, int page_cnt) {
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb = NULL;
    pb_opts.sample_cb = perfCallback;
    pb_opts.lost_cb = perfLostCallback;
    __u64 ctx = map_fd;
    pb_opts.ctx = (void*)ctx;
    pb = perf_buffer__new(map_fd, page_cnt, &pb_opts);
    if (pb < 0) {
        fprintf(stderr, "Failed to initialize perf buffer!\n");
        return NULL;
    }
    return pb;
}

int poke_kprobe_events(bool add, const char* name, bool ret) {
    char buf[256];
    int fd, err;
    char pr;

    fd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
    if (fd < 0) {
        err = -errno;
        fprintf(stderr, "failed to open kprobe_events file: %d\n", err);
        return err;
    }

    pr = ret ? 'r' : 'p';

    if (add)
        snprintf(buf, sizeof(buf), "%c:kprobes/%c%s %s", pr, pr, name, name);
    else
        snprintf(buf, sizeof(buf), "-:kprobes/%c%s", pr, name);

    err = write(fd, buf, strlen(buf));
    if (err < 0) {
        err = -errno;
        fprintf(
            stderr,
            "failed to %s kprobe '%s': %d\n",
            add ? "add" : "remove",
            buf,
            err);
    }
    close(fd);
    return err >= 0 ? 0 : err;
}

int add_kprobe_event(const char* func_name, bool is_kretprobe) {
    return poke_kprobe_events(true, func_name, is_kretprobe);
}

int remove_kprobe_event(const char* func_name, bool is_kretprobe) {
    return poke_kprobe_events(false, func_name, is_kretprobe);
}

struct bpf_link* attach_kprobe_legacy(
    struct bpf_program* prog,
    const char* func_name,
    bool is_kretprobe) {
    char fname[256];
    struct perf_event_attr attr;
    struct bpf_link* link;
    int fd = -1, err, id;
    FILE* f = NULL;
    char pr;

    err = add_kprobe_event(func_name, is_kretprobe);
    if (err) {
        fprintf(stderr, "failed to create kprobe event: %d\n", err);
        return NULL;
    }

	pr = is_kretprobe ? 'r' : 'p';

    snprintf(
        fname,
        sizeof(fname),
        "/sys/kernel/debug/tracing/events/kprobes/%c%s/id",
        pr, func_name);
    f = fopen(fname, "r");
    if (!f) {
        fprintf(stderr, "failed to open kprobe id file '%s': %d\n", fname, -errno);
        goto err_out;
    }

    if (fscanf(f, "%d\n", &id) != 1) {
        fprintf(stderr, "failed to read kprobe id from '%s': %d\n", fname, -errno);
        goto err_out;
    }

    fclose(f);
    f = NULL;

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.config = id;
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        fprintf(
            stderr,
            "failed to create perf event for kprobe ID %d: %d\n",
            id,
            -errno);
        goto err_out;
    }

    link = bpf_program__attach_perf_event(prog, fd);
    err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "failed to attach to perf event FD %d: %d\n", fd, err);
        goto err_out;
    }

    return link;

err_out:
    if (f)
        fclose(f);
    if (fd >= 0)
        close(fd);
    remove_kprobe_event(func_name, is_kretprobe);
    return NULL;
}
*/
import "C"

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type Module struct {
	obj      *C.struct_bpf_object
	links    []*BpfLink
	perfBufs []*PerfBuffer
}

type BpfMap struct {
	name   string
	fd     C.int
	module *Module
}

type BpfProg struct {
	name   string
	prog   *C.struct_bpf_program
	module *Module
}

type LinkType int

const (
	Tracepoint LinkType = iota
	RawTracepoint
	Kprobe
	Kretprobe
	KprobeLegacy
	KretprobeLegacy
)

type BpfLink struct {
	link      *C.struct_bpf_link
	prog      *BpfProg
	linkType  LinkType
	eventName string
}

type PerfBuffer struct {
	pb     *C.struct_perf_buffer
	bpfMap *BpfMap
	stop   chan bool
}

// BPF is using locked memory for BPF maps and various other things.
// By default, this limit is very low - increase to avoid failures
func bumpMemlockRlimit() error {
	var rLimit syscall.Rlimit
	rLimit.Max = 512 << 20 /* 512 MBs */
	rLimit.Cur = 512 << 20 /* 512 MBs */
	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rLimit)
	if err != nil {
		fmt.Errorf("error setting rlimit: %v", err)
	}
	return nil
}

func NewModuleFromFile(bpfObjFile string) (*Module, error) {
	C.set_print_fn()
	bumpMemlockRlimit()
	cs := C.CString(bpfObjFile)
	obj := C.bpf_object__open(cs)
	C.free(unsafe.Pointer(cs))
	if obj == nil {
		return nil, fmt.Errorf("failed to open BPF object %s", bpfObjFile)
	}

	return &Module{
		obj: obj,
	}, nil
}

func NewModuleFromBuffer(bpfObjBuff []byte, bpfObjName string) (*Module, error) {
	C.set_print_fn()
	bumpMemlockRlimit()
	name := C.CString(bpfObjName)
	buffSize := C.size_t(len(bpfObjBuff))
	buffPtr := unsafe.Pointer(C.CBytes(bpfObjBuff))
	obj := C.bpf_object__open_buffer(buffPtr, buffSize, name)
	C.free(unsafe.Pointer(name))
	C.free(unsafe.Pointer(buffPtr))
	if obj == nil {
		return nil, fmt.Errorf("failed to open BPF object %s: %v...", name, bpfObjBuff[:20])
	}

	return &Module{
		obj: obj,
	}, nil
}

func (m *Module) Close() {
	for _, pb := range m.perfBufs {
		C.perf_buffer__free(pb.pb)
	}
	for _, link := range m.links {
		C.bpf_link__destroy(link.link)
		if link.linkType == KprobeLegacy {
			cs := C.CString(link.eventName)
			C.remove_kprobe_event(cs, false)
			C.free(unsafe.Pointer(cs))
		}
		if link.linkType == KretprobeLegacy {
			cs := C.CString(link.eventName)
			C.remove_kprobe_event(cs, true)
			C.free(unsafe.Pointer(cs))
		}
	}
	C.bpf_object__close(m.obj)
}

func (m *Module) BpfLoadObject() error {
	ret := C.bpf_object__load(m.obj)
	if ret != 0 {
		return fmt.Errorf("failed to load BPF object")
	}

	return nil
}

func (m *Module) GetMap(mapName string) (*BpfMap, error) {
	cs := C.CString(mapName)
	bpfMap := C.bpf_object__find_map_by_name(m.obj, cs)
	C.free(unsafe.Pointer(cs))
	if bpfMap == nil {
		return nil, fmt.Errorf("failed to find BPF map %s", mapName)
	}

	return &BpfMap{
		name:   mapName,
		fd:     C.bpf_map__fd(bpfMap),
		module: m,
	}, nil
}

func (b *BpfMap) Update(key, value interface{}) error {
	var keyPtr, valuePtr unsafe.Pointer
	if k, isType := key.(int32); isType {
		keyPtr = unsafe.Pointer(&k)
	} else if k, isType := key.(uint32); isType {
		keyPtr = unsafe.Pointer(&k)
	} else if k, isType := key.(int64); isType {
		keyPtr = unsafe.Pointer(&k)
	} else if k, isType := key.(uint64); isType {
		keyPtr = unsafe.Pointer(&k)
	} else {
		return fmt.Errorf("failed to update map %s: unknown key type %T", b.name, key)
	}
	if v, isType := value.(int32); isType {
		valuePtr = unsafe.Pointer(&v)
	} else if v, isType := value.(uint32); isType {
		valuePtr = unsafe.Pointer(&v)
	} else if v, isType := value.(int64); isType {
		valuePtr = unsafe.Pointer(&v)
	} else if v, isType := value.(uint64); isType {
		valuePtr = unsafe.Pointer(&v)
	} else if v, isType := value.([]byte); isType {
		valuePtr = unsafe.Pointer(&v[0])
	} else {
		return fmt.Errorf("failed to update map %s: unknown value type %T", b.name, value)
	}

	err := C.bpf_map_update_elem(b.fd, keyPtr, valuePtr, C.BPF_ANY)
	if err != 0 {
		return fmt.Errorf("failed to update map %s", b.name)
	}
	return nil
}

func (m *Module) GetProgram(progName string) (*BpfProg, error) {
	cs := C.CString(progName)
	prog := C.bpf_object__find_program_by_name(m.obj, cs)
	C.free(unsafe.Pointer(cs))
	if prog == nil {
		return nil, fmt.Errorf("failed to find BPF program %s", progName)
	}

	return &BpfProg{
		name:   progName,
		prog:   prog,
		module: m,
	}, nil
}

func (p *BpfProg) GetFd() C.int {
	return C.bpf_program__fd(p.prog)
}

// BpfProgType is an enum as defined in https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h
type BpfProgType uint32

const (
	BpfProgTypeUnspec uint32 = iota
	BpfProgTypeSocketFilter
	BpfProgTypeKprobe
	BpfProgTypeSchedCls
	BpfProgTypeSchedAct
	BpfProgTypeTracepoint
	BpfProgTypeXdp
	BpfProgTypePerfEvent
	BpfProgTypeCgroupSkb
	BpfProgTypeCgroupSock
	BpfProgTypeLwtIn
	BpfProgTypeLwtOut
	BpfProgTypeLwtXmit
	BpfProgTypeSockOps
	BpfProgTypeSkSkb
	BpfProgTypeCgroupDevice
	BpfProgTypeSkMsg
	BpfProgTypeRawTracepoint
	BpfProgTypeCgroupSockAddr
	BpfProgTypeLwtSeg6Local
	BpfProgTypeLircMode2
	BpfProgTypeSkReuseport
	BpfProgTypeFlowDissector
	BpfProgTypeCgroupSysctl
	BpfProgTypeRawTracepointWritable
	BpfProgTypeCgroupSockopt
	BpfProgTypeTracing
	BpfProgTypeStructOps
	BpfProgTypeExt
	BpfProgTypeLsm
	BpfProgTypeSkLookup
)

func (p *BpfProg) GetType() uint32 {
	return C.bpf_program__get_type(p.prog)
}

func (p *BpfProg) SetAutoload(autoload bool) error {
	cbool := C.bool(autoload)
	err := C.bpf_program__set_autoload(p.prog, cbool)
	if err != 0 {
		return fmt.Errorf("failed to set bpf program autoload")
	}
	return nil
}

func (p *BpfProg) SetTracepoint() error {
	err := C.bpf_program__set_tracepoint(p.prog)
	if err != 0 {
		return fmt.Errorf("failed to set bpf program as tracepoint")
	}
	return nil
}

func (p *BpfProg) AttachTracepoint(tp string) (*BpfLink, error) {
	tpEvent := strings.Split(tp, ":")
	tpCategory := C.CString(tpEvent[0])
	tpName := C.CString(tpEvent[1])
	link := C.bpf_program__attach_tracepoint(p.prog, tpCategory, tpName)
	C.free(unsafe.Pointer(tpCategory))
	C.free(unsafe.Pointer(tpName))
	if link == nil {
		return nil, fmt.Errorf("failed to attach tracepoint %s to program %s", tp, p.name)
	}

	bpfLink := &BpfLink{
		link:      link,
		prog:      p,
		linkType:  Tracepoint,
		eventName: tp,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BpfProg) AttachRawTracepoint(tpEvent string) (*BpfLink, error) {
	cs := C.CString(tpEvent)
	link := C.bpf_program__attach_raw_tracepoint(p.prog, cs)
	C.free(unsafe.Pointer(cs))
	if link == nil {
		return nil, fmt.Errorf("failed to attach raw tracepoint %s to program", tpEvent, p.name)
	}

	bpfLink := &BpfLink{
		link:      link,
		prog:      p,
		linkType:  RawTracepoint,
		eventName: tpEvent,
	}
	p.module.links = append(p.module.links, bpfLink)
	return bpfLink, nil
}

// this API should be used for kernels > 4.17
func (p *BpfProg) AttachKprobe(kp string) (*BpfLink, error) {
	return doAttachKprobe(p, kp, false)
}

// this API should be used for kernels > 4.17
func (p *BpfProg) AttachKretprobe(kp string) (*BpfLink, error) {
	return doAttachKprobe(p, kp, true)
}

func doAttachKprobe(prog *BpfProg, kp string, isKretprobe bool) (*BpfLink, error) {
	cs := C.CString(kp)
	cbool := C.bool(isKretprobe)
	link := C.bpf_program__attach_kprobe(prog.prog, cbool, cs)
	C.free(unsafe.Pointer(cs))
	if link == nil {
		return nil, fmt.Errorf("failed to attach %s k(ret)probe to program %s", kp, prog.name)
	}

	kpType := Kprobe
	if isKretprobe {
		kpType = Kretprobe
	}

	bpfLink := &BpfLink{
		link:      link,
		prog:      prog,
		linkType:  kpType,
		eventName: kp,
	}
	prog.module.links = append(prog.module.links, bpfLink)
	return bpfLink, nil
}

func (p *BpfProg) AttachKprobeLegacy(kp string) (*BpfLink, error) {
	return doAttachKprobeLegacy(p, kp, false)
}

func (p *BpfProg) AttachKretprobeLegacy(kp string) (*BpfLink, error) {
	return doAttachKprobeLegacy(p, kp, true)
}

func doAttachKprobeLegacy(prog *BpfProg, kp string, isKretprobe bool) (*BpfLink, error) {
	cs := C.CString(kp)
	cbool := C.bool(isKretprobe)
	link := C.attach_kprobe_legacy(prog.prog, cs, cbool)
	C.free(unsafe.Pointer(cs))
	if link == nil {
		return nil, fmt.Errorf("failed to attach %s k(ret)probe using legacy debugfs API", kp)
	}

	kpType := KprobeLegacy
	if isKretprobe {
		kpType = KretprobeLegacy
	}

	bpfLink := &BpfLink{
		link:      link,
		prog:      prog,
		linkType:  kpType,
		eventName: kp,
	}
	prog.module.links = append(prog.module.links, bpfLink)
	return bpfLink, nil
}

var eventChannels = make(map[uintptr]chan []byte)
var lostChannels = make(map[uintptr]chan uint64)

func (m *Module) InitPerfBuf(mapName string, eventsChan chan []byte, lostChan chan uint64, pageCnt int) (*PerfBuffer, error) {
	bpfMap, err := m.GetMap(mapName)
	if err != nil {
		return nil, fmt.Errorf("failed to init perf buffer: %v", err)
	}
	ctx := uintptr(bpfMap.fd)
	if eventsChan == nil {
		return nil, fmt.Errorf("failed to init perf buffer: events channel can not be nil!")
	}
	eventChannels[ctx] = eventsChan
	lostChannels[ctx] = lostChan
	pb := C.init_perf_buf(bpfMap.fd, C.int(pageCnt))
	if pb == nil {
		return nil, fmt.Errorf("failed to initialize perf buffer")
	}

	perfBuf := &PerfBuffer{
		pb:     pb,
		bpfMap: bpfMap,
		stop:   make(chan bool),
	}
	m.perfBufs = append(m.perfBufs, perfBuf)
	return perfBuf, nil
}

func (pb *PerfBuffer) Start() {
	go pb.poll()
}

func (pb *PerfBuffer) Stop() {
	pb.stop <- true
}

func (pb *PerfBuffer) Free() {
	C.perf_buffer__free(pb.pb)
}

// todo: consider writing the perf polling in go as c to go calls (callback) are expensive
func (pb *PerfBuffer) poll() error {
	for {
		select {
		case <-pb.stop:
			return nil
		default:
			err := C.perf_buffer__poll(pb.pb, 300)
			if err < 0 {
				if syscall.Errno(-err) == syscall.EINTR {
					continue
				}
				return fmt.Errorf("Error polling perf buffer: %d", err)
			}
		}
	}
	return nil
}
