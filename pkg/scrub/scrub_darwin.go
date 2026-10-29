//go:build production && darwin

package scrub

import (
	"crypto/rand"
	"reflect"
	"syscall"
	"unsafe"
)

func randomAlphaNumByte() byte {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b [1]byte
	_, _ = rand.Read(b[:])
	return charset[int(b[0])%len(charset)]
}

func protectPages(ptr uintptr, length int, prot int) error {
	if length <= 0 {
		return nil
	}
	pageSize := syscall.Getpagesize()
	pageStart := ptr &^ uintptr(pageSize-1)
	pageEnd := (ptr + uintptr(length) + uintptr(pageSize-1)) &^ uintptr(pageSize-1)
	return syscall.Mprotect(
		unsafe.Slice((*byte)(unsafe.Pointer(pageStart)), pageEnd-pageStart),
		prot,
	)
}

func wipeStringMemory(s string) {
	if len(s) == 0 {
		return
	}
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	if err := protectPages(h.Data, h.Len, syscall.PROT_READ|syscall.PROT_WRITE); err != nil {
		return
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(h.Data)), h.Len)
	for i := range b {
		b[i] = randomAlphaNumByte()
	}
	_ = protectPages(h.Data, h.Len, syscall.PROT_READ)
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
