//go:build production && windows

package antidebug

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procIsDebuggerPresent         = modkernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = modkernel32.NewProc("CheckRemoteDebuggerPresent")
	procGetCurrentProcess         = modkernel32.NewProc("GetCurrentProcess")
)

// IsProduction returns true in production builds.
func IsProduction() bool {
	return true
}

func isWindowsDebugged() bool {
	r, _, _ := procIsDebuggerPresent.Call()
	if r != 0 {
		return true
	}
	var isDebuggerPresent int32
	hProcess, _, _ := procGetCurrentProcess.Call()
	r2, _, _ := procCheckRemoteDebuggerPresent.Call(hProcess, uintptr(unsafe.Pointer(&isDebuggerPresent)))
	if r2 != 0 && isDebuggerPresent != 0 {
		return true
	}
	return false
}

// EnforceProductionSecurity checks for Windows debuggers and runs a watchdog loop.
func EnforceProductionSecurity() {
	if isWindowsDebugged() {
		os.Exit(0)
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if isWindowsDebugged() {
				os.Exit(0)
			}
		}
	}()
}
