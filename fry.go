// Package fry provides binary stripping, rodata inspection, asset encryption,
// runtime memory scrubbing, and anti-tamper capabilities for Wails v3 applications.
package fry

import (
	"embed"
	"fmt"
	"io/fs"
	"os"

	"github.com/simtxng/fry/pkg/antidebug"
	"github.com/simtxng/fry/pkg/assets"
	"github.com/simtxng/fry/pkg/obf"
	"github.com/simtxng/fry/pkg/scrub"
)

// DeriveKey derives the deterministic 32-byte AES-256 key used for asset encryption.
func DeriveKey() [32]byte {
	return assets.DeriveKey()
}

// DecryptAssets decrypts an AES-256-GCM encrypted payload and returns a *zip.Reader as fs.FS.
func DecryptAssets(encrypted []byte) (fs.FS, error) {
	return assets.Decrypt(encrypted, assets.DeriveKey())
}

// PackAssets traverses inputDir, deflates its contents into a zip archive, encrypts it
// using AES-256-GCM, and writes the resulting encrypted container to outputFile.
func PackAssets(inputDir, outputFile string) error {
	return assets.Pack(inputDir, outputFile, assets.DeriveKey())
}

// GetAssetFS resolves the asset filesystem for Wails.
// In production, it extracts and decrypts assetFilename from embedFS.
// In development, if assetFilename is empty or absent, it falls back to the first existing directory in devFallbacks.
func GetAssetFS(embedFS embed.FS, assetFilename string, devFallbacks ...string) (fs.FS, error) {
	if assetFilename != "" {
		data, err := embedFS.ReadFile(assetFilename)
		if err == nil && len(data) > 0 {
			return DecryptAssets(data)
		}
	}

	for _, p := range devFallbacks {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return os.DirFS(p), nil
		}
	}

	return nil, fmt.Errorf("fry: encrypted assets %q not found and dev fallbacks %v missing", assetFilename, devFallbacks)
}

// ScrubRuntimeMetadata scrubs type and method names from .rodata in RAM after
// Wails v3 compiles its numeric ID dispatch table.
func ScrubRuntimeMetadata(services ...any) {
	scrub.ScrubRuntimeMetadata(services...)
}

// EnforceProductionSecurity checks for debuggers/tracers, sets PR_SET_DUMPABLE=0,
// and spawns an active watchdog. Safe no-op in dev/test builds.
func EnforceProductionSecurity() {
	antidebug.EnforceProductionSecurity()
}

// IsProduction returns true if compiled with -tags production on a supported platform.
func IsProduction() bool {
	return antidebug.IsProduction()
}

// Obf obfuscates a plain string into a byte slice using position-indexed XOR.
func Obf(plain string, key byte) []byte {
	return obf.Obf(plain, key)
}

// Deobf recovers an obfuscated byte slice into a string using position-indexed XOR.
func Deobf(data []byte, key byte) string {
	return obf.Deobf(data, key)
}
