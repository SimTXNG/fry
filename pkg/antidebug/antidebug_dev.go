//go:build !production || (!linux && !windows && !darwin)

package antidebug

// IsProduction returns false in development builds.
func IsProduction() bool {
	return false
}

// EnforceProductionSecurity is a no-op in non-production builds.
func EnforceProductionSecurity() {
}
