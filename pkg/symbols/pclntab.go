package symbols

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func randomChar() byte {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	var b [1]byte
	_, _ = rand.Read(b[:])
	return charset[int(b[0])%len(charset)]
}

// StripPCLnTab scrambles function names and source file paths in Go's .gopclntab table.
func StripPCLnTab(secData []byte, mode string) (int, int, error) {
	if len(secData) < 16 {
		return 0, 0, fmt.Errorf("section data too short (%d bytes)", len(secData))
	}

	magic := binary.LittleEndian.Uint32(secData[0:4])
	if magic != 0xfffffff1 && magic != 0xfffffff0 && magic != 0xfffffffa && magic != 0xfffffffb {
		return 0, 0, fmt.Errorf("unsupported pclntab magic: 0x%x", magic)
	}

	ptrsize := uint32(secData[7])
	if ptrsize != 4 && ptrsize != 8 {
		return 0, 0, fmt.Errorf("unsupported pointer size: %d", ptrsize)
	}

	offset := func(word uint32) uint64 {
		if ptrsize == 4 {
			return uint64(binary.LittleEndian.Uint32(secData[8+word*ptrsize:]))
		}
		return binary.LittleEndian.Uint64(secData[8+word*ptrsize:])
	}

	var funcnametabOff, cutabOff, filetabOff, pctabOff uint64
	if magic == 0xfffffff1 || magic == 0xfffffff0 { // Go 1.18, 1.20+
		funcnametabOff = offset(3)
		cutabOff = offset(4)
		filetabOff = offset(5)
		pctabOff = offset(6)
	} else if magic == 0xfffffffa { // Go 1.16
		funcnametabOff = offset(2)
		cutabOff = offset(3)
		filetabOff = offset(4)
		pctabOff = offset(5)
	} else {
		return 0, 0, fmt.Errorf("legacy Go 1.2 pclntab stripping not supported")
	}

	if cutabOff > uint64(len(secData)) || pctabOff > uint64(len(secData)) {
		return 0, 0, fmt.Errorf("table offsets exceed section size (cutab: %d, pctab: %d, total: %d)", cutabOff, pctabOff, len(secData))
	}

	var funcCharsWiped, fileCharsWiped int

	for i := funcnametabOff; i < cutabOff; i++ {
		if secData[i] != 0 {
			if mode == "random" {
				secData[i] = randomChar()
			} else {
				secData[i] = 'x'
			}
			funcCharsWiped++
		}
	}

	for i := filetabOff; i < pctabOff; i++ {
		if secData[i] != 0 {
			if mode == "random" {
				secData[i] = randomChar()
			} else {
				secData[i] = 'x'
			}
			fileCharsWiped++
		}
	}

	return funcCharsWiped, fileCharsWiped, nil
}

// StripFile strips .gopclntab in an ELF or PE binary.
func StripFile(inPath, outPath, mode string) (int, int, error) {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return 0, 0, fmt.Errorf("reading file: %w", err)
	}

	if ef, err := elf.Open(inPath); err == nil {
		defer ef.Close()
		sec := ef.Section(".gopclntab")
		if sec == nil {
			return 0, 0, fmt.Errorf("no .gopclntab section in ELF")
		}
		secData := data[sec.Offset : sec.Offset+sec.Size]
		funcWiped, fileWiped, err := StripPCLnTab(secData, mode)
		if err != nil {
			return 0, 0, err
		}
		if err := os.WriteFile(outPath, data, 0755); err != nil {
			return 0, 0, fmt.Errorf("writing output: %w", err)
		}
		return funcWiped, fileWiped, nil
	}

	if pf, err := pe.Open(inPath); err == nil {
		defer pf.Close()
		for _, sec := range pf.Sections {
			name := strings.TrimRight(sec.Name, "\x00")
			if name == ".gopclntab" {
				secData := data[sec.Offset : sec.Offset+sec.Size]
				funcWiped, fileWiped, err := StripPCLnTab(secData, mode)
				if err != nil {
					return 0, 0, err
				}
				if err := os.WriteFile(outPath, data, 0755); err != nil {
					return 0, 0, fmt.Errorf("writing output: %w", err)
				}
				return funcWiped, fileWiped, nil
			}
		}

		// Embedded in other section
		for _, sec := range pf.Sections {
			sData := data[sec.Offset : sec.Offset+sec.Size]
			magics := [][]byte{{0xf1, 0xff, 0xff, 0xff}, {0xf0, 0xff, 0xff, 0xff}}
			for _, m := range magics {
				if idx := bytes.Index(sData, m); idx != -1 && idx+16 <= len(sData) {
					funcWiped, fileWiped, err := StripPCLnTab(sData[idx:], mode)
					if err == nil {
						if err := os.WriteFile(outPath, data, 0755); err != nil {
							return 0, 0, fmt.Errorf("writing output: %w", err)
						}
						return funcWiped, fileWiped, nil
					}
				}
			}
		}
	}

	return 0, 0, fmt.Errorf("unsupported binary format or .gopclntab not found")
}

// Dump prints symbol summary for a Go binary.
func Dump(binPath string, filter string, limit int) error {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}

	var pclnData []byte
	var isELF bool
	if ef, err := elf.Open(binPath); err == nil {
		defer ef.Close()
		isELF = true
		if sec := ef.Section(".gopclntab"); sec != nil {
			pclnData = data[sec.Offset : sec.Offset+sec.Size]
		}
	} else if pf, err := pe.Open(binPath); err == nil {
		defer pf.Close()
		for _, sec := range pf.Sections {
			if strings.TrimRight(sec.Name, "\x00") == ".gopclntab" {
				pclnData = data[sec.Offset : sec.Offset+sec.Size]
				break
			}
		}
	}

	if len(pclnData) < 16 {
		return fmt.Errorf("no valid .gopclntab found in %s", binPath)
	}

	magic := binary.LittleEndian.Uint32(pclnData[0:4])
	ptrsize := uint32(pclnData[7])
	offset := func(word uint32) uint64 {
		if ptrsize == 4 {
			return uint64(binary.LittleEndian.Uint32(pclnData[8+word*ptrsize:]))
		}
		return binary.LittleEndian.Uint64(pclnData[8+word*ptrsize:])
	}

	var nfunc uint64
	var funcnametabOff, cutabOff uint64
	if magic == 0xfffffff1 || magic == 0xfffffff0 {
		nfunc = offset(0)
		funcnametabOff = offset(3)
		cutabOff = offset(4)
	} else {
		nfunc = offset(0)
		funcnametabOff = offset(2)
		cutabOff = offset(3)
	}

	fmt.Println("================================================================================")
	fmt.Printf(" Go Symbol Table Dump (.gopclntab) - %s\n", filepath.Base(binPath))
	fmt.Println("================================================================================")
	fmt.Printf(" Format:             %s\n", func() string {
		if isELF {
			return "ELF (Linux)"
		}
		return "PE (Windows)"
	}())
	fmt.Printf(" Magic:              0x%x (ptrsize: %d)\n", magic, ptrsize)
	fmt.Printf(" Total Functions:    %d\n", nfunc)

	var funcNames []string
	if cutabOff <= uint64(len(pclnData)) && funcnametabOff < cutabOff {
		raw := pclnData[funcnametabOff:cutabOff]
		parts := bytes.Split(raw, []byte{0})
		for _, p := range parts {
			if len(p) > 0 {
				s := string(p)
				if filter == "" || strings.Contains(s, filter) {
					funcNames = append(funcNames, s)
				}
			}
		}
	}

	// Calculate unique packages
	pkgMap := make(map[string]int)
	for _, fn := range funcNames {
		if idx := strings.LastIndex(fn, "/"); idx != -1 {
			pkg := fn[:idx]
			pkgMap[pkg]++
		} else if idx := strings.Index(fn, "."); idx != -1 {
			pkg := fn[:idx]
			pkgMap[pkg]++
		}
	}

	fmt.Printf(" Matched Functions:  %d (filter: %q)\n", len(funcNames), filter)
	fmt.Printf(" Unique Packages:    %d\n", len(pkgMap))
	fmt.Println("================================================================================")

	count := len(funcNames)
	if limit > 0 && limit < count {
		count = limit
	}

	for i := 0; i < count; i++ {
		fmt.Printf("  [%5d] %s\n", i+1, funcNames[i])
	}
	if len(funcNames) > count {
		fmt.Printf("  ... [%d more functions omitted; use --limit 0 for full dump]\n", len(funcNames)-count)
	}

	if len(pkgMap) > 0 && len(pkgMap) <= 30 {
		fmt.Println("\n--- Packages ---")
		var pkgs []string
		for p := range pkgMap {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		for _, p := range pkgs {
			fmt.Printf("  %5d  %s\n", pkgMap[p], p)
		}
	}

	return nil
}
