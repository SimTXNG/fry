//go:build production && darwin

package antidebug

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

// IsProduction returns true in production builds.
func IsProduction() bool {
	return true
}

func isDarwinTraced() bool {
	var mib = [4]int32{1 /* CTL_KERN */, 14 /* KERN_PROC */, 1 /* KERN_PROC_PID */, int32(os.Getpid())}
	type kinfoProc struct {
		pad  [32]byte
		flag int32
		pad2 [452]byte
	}
	var kp kinfoProc
	var size = uintptr(unsafe.Sizeof(kp))
	_, _, err := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		uintptr(unsafe.Pointer(&kp)),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	if err != 0 {
		return false
	}
	const pTraced = 0x00000800
	return (kp.flag & pTraced) != 0
}

// EnforceProductionSecurity checks for macOS debuggers and runs a watchdog loop.
func EnforceProductionSecurity() {
	if isDarwinTraced() {
		os.Exit(0)
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if isDarwinTraced() {
				os.Exit(0)
			}
		}
	}()
}
