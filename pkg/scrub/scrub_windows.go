//go:build production && windows

package scrub

import (
	"crypto/rand"
	"reflect"
	"syscall"
	"unsafe"
)

var (
	modkernel32        = syscall.NewLazyDLL("kernel32.dll")
	procVirtualProtect = modkernel32.NewProc("VirtualProtect")
)

const (
	pageReadWrite = 0x04
	pageReadOnly  = 0x02
)

func randomAlphaNumByte() byte {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b [1]byte
	_, _ = rand.Read(b[:])
	return charset[int(b[0])%len(charset)]
}

func wipeStringMemory(s string) {
	if len(s) == 0 {
		return
	}
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	if h.Len == 0 || h.Data == 0 {
		return
	}

	var oldProtect uint32
	r1, _, _ := procVirtualProtect.Call(
		h.Data,
		uintptr(h.Len),
		uintptr(pageReadWrite),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r1 == 0 {
		return
	}

	b := unsafe.Slice((*byte)(unsafe.Pointer(h.Data)), h.Len)
	for i := range b {
		b[i] = randomAlphaNumByte()
	}

	var temp uint32
	procVirtualProtect.Call(
		h.Data,
		uintptr(h.Len),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&temp)),
	)
}

func ScrubRuntimeMetadata(services ...any) {
	var stringsToWipe []string
	for _, svc := range services {
		if svc == nil {
			continue
		}
		t := reflect.TypeOf(svc)
		if t == nil {
			continue
		}
		stringsToWipe = append(stringsToWipe, t.String())
		for i := 0; i < t.NumMethod(); i++ {
			stringsToWipe = append(stringsToWipe, t.Method(i).Name)
		}
	}
	for _, s := range stringsToWipe {
		wipeStringMemory(s)
	}
}
