//go:build production && linux

package antidebug

import (
	"bytes"
	"os"
	"syscall"
	"time"
)

// IsProduction returns true in production builds.
func IsProduction() bool {
	return true
}

func isLinuxTraced() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("TracerPid:")) {
			parts := bytes.Fields(line)
			if len(parts) >= 2 && !bytes.Equal(parts[1], []byte("0")) {
				return true
			}
			break
		}
	}
	return false
}

// EnforceProductionSecurity checks for debuggers, disables core dumps via PR_SET_DUMPABLE=0,
// and spawns a background watchdog.
func EnforceProductionSecurity() {
	if isLinuxTraced() {
		os.Exit(0)
	}

	const prSetDumpable = 0x4
	_, _, _ = syscall.Syscall(syscall.SYS_PRCTL, uintptr(prSetDumpable), 0, 0)

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if isLinuxTraced() {
				os.Exit(0)
			}
		}
	}()
}
