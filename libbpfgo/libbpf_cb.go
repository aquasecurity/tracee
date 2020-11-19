package libbpfgo

import (
	"C"
	"unsafe"
)

// This callback definition needs to be in a different file from where it is declared in C
// Otherwise, multiple definition compilation error will occur

//export perfCallback
func perfCallback(ctx unsafe.Pointer, cpu C.int, data unsafe.Pointer, size C.int) {
	eventChannels[uintptr(ctx)] <- C.GoBytes(data, size)
}

//export perfLostCallback
func perfLostCallback(ctx unsafe.Pointer, cpu C.int, cnt C.ulonglong) {
	lostChan := lostChannels[uintptr(ctx)]
	if lostChan != nil {
		lostChan <- uint64(cnt)
	}
}
