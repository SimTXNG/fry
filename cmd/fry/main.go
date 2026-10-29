package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/simtxng/fry"
	"github.com/simtxng/fry/pkg/assets"
	"github.com/simtxng/fry/pkg/obf"
	"github.com/simtxng/fry/pkg/rodata"
	"github.com/simtxng/fry/pkg/symbols"
)

const usageText = `fry - Wails v3 Application Hardening & Stripping Toolkit

Usage:
  fry <command> [options] [arguments...]

Commands:
  dump rodata     Audit .rodata, .typelink, struct schemas, and sensitive strings
  dump syms       Audit .gopclntab functions, packages, and file locations
  pack assets     Pack and encrypt frontend directory into an AES-256-GCM container
  strip           Strip .gopclntab symbols and .typelink metadata (all-in-one)
  strip symbols   Scramble function names and file paths in .gopclntab
  strip rodata    Zero .typelink and clear moduledata.typelinks [len, cap]
  string obf      Generate obfuscated Go byte slice for sensitive string
  string deobf    Deobfuscate a byte sequence into plain text
  version         Print fry version
`

func resolveBinaryTarget(inPath string) string {
	if _, err := os.Stat(inPath); err == nil {
		return inPath
	}
	if _, err := os.Stat(inPath + ".exe"); err == nil {
		return inPath + ".exe"
	}
	return inPath
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usageText)
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "dump":
		runDump(args)
	case "pack":
		runPack(args)
	case "strip":
		runStrip(args)
	case "string":
		runString(args)
	case "version":
		fmt.Println("fry v0.1.0 (wails3 binary hardening toolkit)")
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "fry: unknown command %q\nRun 'fry help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func runDump(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: fry dump <rodata|syms> [options] <binary>\n")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "rodata":
		fs := flag.NewFlagSet("fry dump rodata", flag.ExitOnError)
		filter := fs.String("filter", "", "Filter types by substring (e.g., 'backend')")
		structs := fs.Bool("structs", false, "Show struct field schemas and tags")
		methods := fs.Bool("methods", false, "Show detailed method lists")
		stringsFlag := fs.Bool("strings", false, "Show sensitive string hits")
		jsonFlag := fs.Bool("json", false, "Output report as JSON")
		limit := fs.Int("limit", 0, "Limit number of displayed types (0 for unlimited)")
		fs.Parse(subArgs)

		if fs.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Usage: fry dump rodata [options] <binary>\n")
			fs.PrintDefaults()
			os.Exit(1)
		}
		target := resolveBinaryTarget(fs.Arg(0))
		if err := rodata.Dump(target, *filter, *structs, *methods, *stringsFlag, *jsonFlag, *limit); err != nil {
			fmt.Fprintf(os.Stderr, "fry dump rodata error: %v\n", err)
			os.Exit(1)
		}

	case "syms", "symbols":
		fs := flag.NewFlagSet("fry dump syms", flag.ExitOnError)
		filter := fs.String("filter", "", "Filter function names by substring")
		limit := fs.Int("limit", 50, "Limit number of displayed functions (0 for unlimited)")
		fs.Parse(subArgs)

		if fs.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Usage: fry dump syms [options] <binary>\n")
			fs.PrintDefaults()
			os.Exit(1)
		}
		target := resolveBinaryTarget(fs.Arg(0))
		if err := symbols.Dump(target, *filter, *limit); err != nil {
			fmt.Fprintf(os.Stderr, "fry dump syms error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "fry dump: unknown target %q (choose 'rodata' or 'syms')\n", sub)
		os.Exit(1)
	}
}

func runPack(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: fry pack assets [options]\n")
		os.Exit(1)
	}

	sub := args[0]
	subArgs := args[1:]

	if sub != "assets" {
		fmt.Fprintf(os.Stderr, "fry pack: unknown target %q (currently 'assets' supported)\n", sub)
		os.Exit(1)
	}

	fs := flag.NewFlagSet("fry pack assets", flag.ExitOnError)
	inputDir := fs.String("input", "dist", "Input directory containing compiled frontend assets")
	inAlias := fs.String("in", "", "Alias for --input")
	outputFile := fs.String("output", "assets.enc", "Output encrypted container path")
	outAlias := fs.String("out", "", "Alias for --output")
	fs.Parse(subArgs)

	in := *inputDir
	if *inAlias != "" {
		in = *inAlias
	}
	out := *outputFile
	if *outAlias != "" {
		out = *outAlias
	}

	if _, err := os.Stat(in); os.IsNotExist(err) {
		// Try frontend/dist
		if _, err := os.Stat("frontend/dist"); err == nil {
			in = "frontend/dist"
		}
	}

	key := assets.DeriveKey()
	if err := assets.Pack(in, out, key); err != nil {
		fmt.Fprintf(os.Stderr, "fry pack assets error: %v\n", err)
		os.Exit(1)
	}
}

func runStrip(args []string) {
	mode := "random"
	stripSyms := true
	stripRodata := true

	var binaryTargets []string

	if len(args) > 0 && args[0] == "symbols" {
		stripRodata = false
		args = args[1:]
	} else if len(args) > 0 && args[0] == "rodata" {
		stripSyms = false
		args = args[1:]
	}

	fs := flag.NewFlagSet("fry strip", flag.ExitOnError)
	modeFlag := fs.String("mode", "random", "Scramble mode: 'random' or 'x'")
	fs.Parse(args)
	mode = *modeFlag

	binaryTargets = fs.Args()
	if len(binaryTargets) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: fry strip [symbols|rodata] [options] <binary-paths...>\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	for _, rawPath := range binaryTargets {
		target := resolveBinaryTarget(rawPath)
		if _, err := os.Stat(target); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "fry strip: target %s not found (skipping)\n", rawPath)
			continue
		}

		var funcWiped, fileWiped, typelinkWiped int
		if stripSyms {
			var err error
			funcWiped, fileWiped, err = symbols.StripFile(target, target, mode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fry strip: symbols error on %s: %v\n", target, err)
				os.Exit(1)
			}
		}

		if stripRodata {
			var err error
			typelinkWiped, err = rodata.StripTypelinks(target, target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fry strip: rodata error on %s: %v\n", target, err)
				os.Exit(1)
			}
		}

		fmt.Printf("fry strip: %s (scrambled %d func chars, %d file chars, zeroed %d typelinks)\n",
			filepath.Base(target), funcWiped, fileWiped, typelinkWiped)
	}
}

func runString(args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: fry string <obf|deobf> <value> [-key <hex/byte>]\n")
		os.Exit(1)
	}

	action := args[0]
	value := args[1]
	key := byte(0x5A)

	if len(args) >= 4 && (args[2] == "-key" || args[2] == "--key") {
		kStr := args[3]
		kStr = strings.TrimPrefix(kStr, "0x")
		if kVal, err := strconv.ParseUint(kStr, 16, 8); err == nil {
			key = byte(kVal)
		}
	}

	switch action {
	case "obf":
		cipher := obf.Obf(value, key)
		fmt.Printf("Plain: %s\n", value)
		fmt.Printf("Key:   0x%02X\n", key)
		fmt.Printf("Go:    fry.Deobf([]byte{")
		for i, b := range cipher {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("0x%02X", b)
		}
		fmt.Printf("}, 0x%02X)\n", key)
	case "deobf":
		cleanHex := strings.ReplaceAll(value, "0x", "")
		cleanHex = strings.ReplaceAll(cleanHex, ",", "")
		cleanHex = strings.ReplaceAll(cleanHex, " ", "")
		raw, err := hex.DecodeString(cleanHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid hex string: %v\n", err)
			os.Exit(1)
		}
		plain := fry.Deobf(raw, key)
		fmt.Printf("Recovered: %s\n", plain)
	default:
		fmt.Fprintf(os.Stderr, "fry string: unknown action %q (choose 'obf' or 'deobf')\n", action)
		os.Exit(1)
	}
}
