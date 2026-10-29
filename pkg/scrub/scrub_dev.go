//go:build !production || (!linux && !windows && !darwin)

package scrub

// ScrubRuntimeMetadata is a no-op in non-production builds so developers
// retain full reflection, debugging, and panic traces.
func ScrubRuntimeMetadata(services ...any) {
}
