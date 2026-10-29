# fry 🍟

> Binary stripping, rodata zeroing, asset encryption, and runtime memory scrubbing toolkit for Wails v3 applications.

`fry` is designed to be the security companion to [`cook`](https://github.com/simtxng/cook) for Go + Wails v3 desktop applications:
- **Cook it**: builds frontend, compiles Go binaries, and packages desktop installers.
- **Fry it**: encrypts virtual assets, scrambles runtime function symbols, zeroes type descriptor metadata, and shreds in-memory service names.

---

## CLI Usage

### Audit & Inspection
```bash
# Audit Go type descriptors, struct schemas, and method tables in .rodata
fry dump rodata bin/simtx

# Audit Go runtime function symbols and source file locations in .gopclntab
fry dump syms bin/simtx
```

### Asset Packing & Encryption
```bash
# Traverse compiled frontend directory, compress into zip, and encrypt with AES-256-GCM
fry pack assets --input frontend/dist --output backend/security/assets.enc
```

### Binary Hardening & Stripping
```bash
# Strip both .gopclntab symbols and .typelink metadata (recommended post-build hook)
fry strip bin/simtx bin/simtx-cli

# Or strip individual components
fry strip symbols bin/simtx
fry strip rodata bin/simtx
```

### String Obfuscation Helper
```bash
# Generate position-indexed XOR byte slice for Go code
fry string obf "https://auth.simtx.net" -key 0x7E
```

---

## Go Runtime Package

Import `github.com/simtx/fry` into your Wails v3 application:

```go
package main

import (
	"embed"
	"github.com/simtx/fry"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed assets.enc*
var assetsFS embed.FS

func main() {
	// 1. Anti-debugging & anti-tamper (Linux, Windows, Darwin)
	fry.EnforceProductionSecurity()

	// 2. Decrypt virtual filesystem in RAM
	vfs, err := fry.GetAssetFS(assetsFS, "assets.enc", "frontend/dist")
	if err != nil {
		panic(err)
	}

	app := application.New(application.Options{
		Services: []application.Service{
			application.NewService(&MyService{}),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(vfs),
		},
	})

	// 3. Shred type & method strings from RAM once Wails builds numeric dispatch map
	fry.ScrubRuntimeMetadata(&MyService{})

	app.Run()
}
```

---

## License

MIT (c) 2026 SimTX
