package rodata

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

type FieldInfo struct {
	Name   string `json:"name"`
	Tag    string `json:"tag,omitempty"`
	Offset uint64 `json:"offset"`
}

type MethodInfo struct {
	Name     string `json:"name"`
	Exported bool   `json:"exported"`
	Ifn      int32  `json:"ifn,omitempty"`
	Tfn      int32  `json:"tfn,omitempty"`
}

type TypeInfo struct {
	Name     string       `json:"name"`
	PkgPath  string       `json:"pkg_path,omitempty"`
	Kind     string       `json:"kind"`
	KindID   int          `json:"kind_id"`
	Size     uint64       `json:"size"`
	Fields   []FieldInfo  `json:"fields,omitempty"`
	Methods  []MethodInfo `json:"methods,omitempty"`
	IsCustom bool         `json:"is_custom"`
}

type RoDataReport struct {
	BinaryPath    string     `json:"binary_path"`
	RoDataSize    uint64     `json:"rodata_size"`
	TotalTypes    int        `json:"total_types"`
	CustomTypes   int        `json:"custom_types"`
	CustomMethods int        `json:"custom_methods"`
	CustomStructs int        `json:"custom_structs"`
	Types         []TypeInfo `json:"types,omitempty"`
	TopStrings    []string   `json:"top_strings,omitempty"`
	SensitiveHits []string   `json:"sensitive_hits,omitempty"`
}

var kindNames = map[int]string{
	1: "bool", 2: "int", 3: "int8", 4: "int16", 5: "int32", 6: "int64",
	7: "uint", 8: "uint8", 9: "uint16", 10: "uint32", 11: "uint64", 12: "uintptr",
	13: "float32", 14: "float64", 15: "complex64", 16: "complex128",
	17: "array", 18: "chan", 19: "func", 20: "interface", 21: "map",
	22: "pointer", 23: "slice", 24: "string", 25: "struct", 26: "unsafePointer",
}

func readVarint(data []byte, pos int) (int, int) {
	v := 0
	shift := 0
	for {
		if pos >= len(data) {
			return 0, pos
		}
		b := data[pos]
		pos++
		v |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return v, pos
}

func readNameAndTag(data []byte, offset int) (string, string) {
	if offset < 0 || offset >= len(data) {
		return "", ""
	}
	flags := data[offset]
	pos := offset + 1
	nameLen, pos := readVarint(data, pos)
	if nameLen <= 0 || pos+nameLen > len(data) {
		return "", ""
	}
	name := string(data[pos : pos+nameLen])
	pos += nameLen

	tag := ""
	if (flags & 0x02) != 0 {
		tagLen, tagPos := readVarint(data, pos)
		if tagLen > 0 && tagPos+tagLen <= len(data) {
			tag = string(data[tagPos : tagPos+tagLen])
		}
	}
	return name, tag
}

func extractPrintableStrings(data []byte, minLen int) []string {
	var results []string
	var current strings.Builder

	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			current.WriteByte(b)
		} else {
			if current.Len() >= minLen {
				results = append(results, current.String())
			}
			current.Reset()
		}
	}
	if current.Len() >= minLen {
		results = append(results, current.String())
	}
	return results
}

// StripTypelinks zeroes out .typelink and clears firstmoduledata.typelinks [len, cap].
func StripTypelinks(inPath, outPath string) (int, error) {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return 0, fmt.Errorf("reading file: %w", err)
	}

	// ELF (Linux)
	if ef, err := elf.Open(inPath); err == nil {
		defer ef.Close()
		tlSec := ef.Section(".typelink")
		if tlSec == nil {
			return 0, fmt.Errorf("no .typelink section in ELF")
		}

		for i := tlSec.Offset; i < tlSec.Offset+tlSec.Size; i++ {
			data[i] = 0
		}
		typelinkWiped := int(tlSec.Size / 4)

		needle := make([]byte, 8)
		binary.LittleEndian.PutUint64(needle, tlSec.Addr)
		for _, sec := range ef.Sections {
			if sec.Flags&elf.SHF_WRITE != 0 && sec.Type != elf.SHT_NOBITS && sec.Offset+sec.Size <= uint64(len(data)) {
				sdata := data[sec.Offset : sec.Offset+sec.Size]
				for idx := 0; idx+24 <= len(sdata); {
					match := bytes.Index(sdata[idx:], needle)
					if match == -1 {
						break
					}
					cur := idx + match
					for k := sec.Offset + uint64(cur) + 8; k < sec.Offset+uint64(cur)+24; k++ {
						data[k] = 0
					}
					idx = cur + 8
				}
			}
		}

		if err := os.WriteFile(outPath, data, 0755); err != nil {
			return 0, fmt.Errorf("writing output: %w", err)
		}
		return typelinkWiped, nil
	}

	// PE (Windows)
	if pf, err := pe.Open(inPath); err == nil {
		defer pf.Close()
		var tlAddr uint64
		typelinkWiped := 0
		for _, sec := range pf.Sections {
			name := strings.TrimRight(sec.Name, "\x00")
			if name == ".typelink" {
				for i := sec.Offset; i < sec.Offset+sec.Size; i++ {
					data[i] = 0
				}
				typelinkWiped = int(sec.Size / 4)
				var imageBase uint64
				if oh64, ok := pf.OptionalHeader.(*pe.OptionalHeader64); ok {
					imageBase = oh64.ImageBase
				} else if oh32, ok := pf.OptionalHeader.(*pe.OptionalHeader32); ok {
					imageBase = uint64(oh32.ImageBase)
				}
				tlAddr = imageBase + uint64(sec.VirtualAddress)
			}
		}

		if tlAddr != 0 {
			needle := make([]byte, 8)
			binary.LittleEndian.PutUint64(needle, tlAddr)
			for _, sec := range pf.Sections {
				if sec.Characteristics&0x80000000 != 0 && uint64(sec.Offset)+uint64(sec.Size) <= uint64(len(data)) {
					sdata := data[sec.Offset : sec.Offset+sec.Size]
					for idx := 0; idx+24 <= len(sdata); {
						match := bytes.Index(sdata[idx:], needle)
						if match == -1 {
							break
						}
						cur := idx + match
						for k := uint64(sec.Offset) + uint64(cur) + 8; k < uint64(sec.Offset)+uint64(cur)+24; k++ {
							data[k] = 0
						}
						idx = cur + 8
					}
				}
			}
		}

		if err := os.WriteFile(outPath, data, 0755); err != nil {
			return 0, fmt.Errorf("writing output: %w", err)
		}
		return typelinkWiped, nil
	}

	return 0, fmt.Errorf("unsupported binary format")
}

// Dump performs a full reverse-engineering audit of .rodata in a binary.
func Dump(binPath string, filter string, showStructs, showMethods, showStrings, asJSON bool, limit int) error {
	f, err := os.Open(binPath)
	if err != nil {
		return fmt.Errorf("opening binary: %w", err)
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return fmt.Errorf("parsing ELF: %w", err)
	}
	defer ef.Close()

	roSec := ef.Section(".rodata")
	if roSec == nil {
		return fmt.Errorf("no .rodata section found")
	}
	roData, err := roSec.Data()
	if err != nil {
		return fmt.Errorf("reading .rodata: %w", err)
	}

	tlSec := ef.Section(".typelink")
	if tlSec == nil {
		return fmt.Errorf("no .typelink section found")
	}
	tlData, err := tlSec.Data()
	if err != nil {
		return fmt.Errorf("reading .typelink: %w", err)
	}

	vaddrToOffset := func(vaddr uint64) int {
		for _, s := range ef.Sections {
			if vaddr >= s.Addr && vaddr < s.Addr+s.Size {
				return int(s.Offset + (vaddr - s.Addr))
			}
		}
		return -1
	}

	var typesVaddr uint64
	var typesFileOffset int

	targetBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(targetBytes, tlSec.Addr)

	for _, s := range ef.Sections {
		sdata, err := s.Data()
		if err != nil {
			continue
		}
		idx := bytes.Index(sdata, targetBytes)
		if idx >= 64 {
			candidateTypes := binary.LittleEndian.Uint64(sdata[idx-64 : idx-56])
			if candidateTypes >= roSec.Addr && candidateTypes < roSec.Addr+roSec.Size {
				typesVaddr = candidateTypes
				typesFileOffset = int(roSec.Offset + (typesVaddr - roSec.Addr))
				break
			}
		}
	}

	if typesVaddr == 0 {
		typesVaddr = roSec.Addr
		typesFileOffset = int(roSec.Offset)
	}

	numEntries := len(tlData) / 4
	report := RoDataReport{
		BinaryPath: binPath,
		RoDataSize: roSec.Size,
		TotalTypes: numEntries,
	}

	fileBytes, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading full binary: %w", err)
	}

	getNameAt := func(typesRelOffset int) (string, string) {
		absOffset := typesFileOffset + typesRelOffset
		if absOffset < 0 || absOffset >= len(fileBytes) {
			return "", ""
		}
		return readNameAndTag(fileBytes, absOffset)
	}

	getNameFromVaddr := func(vaddr uint64) (string, string) {
		fileOff := vaddrToOffset(vaddr)
		if fileOff < 0 || fileOff >= len(fileBytes) {
			return "", ""
		}
		return readNameAndTag(fileBytes, fileOff)
	}

	for i := 0; i < numEntries; i++ {
		typeOffset := int(int32(binary.LittleEndian.Uint32(tlData[i*4 : (i+1)*4])))
		if typeOffset == 0 {
			continue
		}
		absTypeOffset := typesFileOffset + typeOffset
		if absTypeOffset < 0 || absTypeOffset+48 > len(fileBytes) {
			continue
		}

		typeDescriptor := fileBytes[absTypeOffset:]
		size := binary.LittleEndian.Uint64(typeDescriptor[0:8])
		kindByte := typeDescriptor[23]
		kindID := int(kindByte & 0x1f)
		tflag := typeDescriptor[20]
		hasExtraStar := (tflag & 0x02) != 0

		strNameOff := int(int32(binary.LittleEndian.Uint32(typeDescriptor[32:36])))
		typeName, _ := getNameAt(strNameOff)
		if hasExtraStar && strings.HasPrefix(typeName, "*") {
			typeName = typeName[1:]
		}

		kindName := kindNames[kindID]
		if kindName == "" {
			kindName = fmt.Sprintf("unknown(%d)", kindID)
		}

		isCustom := false
		if strings.Contains(typeName, "backend") ||
			strings.Contains(typeName, "simtx") ||
			strings.Contains(typeName, "main.") ||
			strings.Contains(typeName, "api.") ||
			strings.Contains(typeName, "proto") {
			isCustom = true
		}

		info := TypeInfo{
			Name:     typeName,
			Kind:     kindName,
			KindID:   kindID,
			Size:     size,
			IsCustom: isCustom,
		}

		if kindID == 25 { // struct
			fieldCount := int(binary.LittleEndian.Uint64(typeDescriptor[48:56]))
			fieldsOffset := absTypeOffset + 56
			for fi := 0; fi < fieldCount; fi++ {
				entryOffset := fieldsOffset + fi*24
				if entryOffset+24 > len(fileBytes) {
					break
				}
				fieldNameOff := int(int32(binary.LittleEndian.Uint32(fileBytes[entryOffset : entryOffset+4])))
				fieldName, fieldTag := getNameAt(fieldNameOff)
				offsetVal := binary.LittleEndian.Uint64(fileBytes[entryOffset+16 : entryOffset+24])

				info.Fields = append(info.Fields, FieldInfo{
					Name:   fieldName,
					Tag:    fieldTag,
					Offset: offsetVal,
				})
			}
			if isCustom && len(info.Fields) > 0 {
				report.CustomStructs++
			}
		}

		uncommonOffset := 48
		if kindID == 25 {
			uncommonOffset = 56 + len(info.Fields)*24
		}
		if (tflag&0x01) != 0 && absTypeOffset+uncommonOffset+16 <= len(fileBytes) {
			uncommonData := fileBytes[absTypeOffset+uncommonOffset:]
			pkgPathOff := int(int32(binary.LittleEndian.Uint32(uncommonData[0:4])))
			pkgPath, _ := getNameAt(pkgPathOff)
			info.PkgPath = pkgPath

			mcount := int(binary.LittleEndian.Uint16(uncommonData[4:6]))
			moff := int(binary.LittleEndian.Uint32(uncommonData[8:12]))

			methodsBase := absTypeOffset + uncommonOffset + moff
			for mi := 0; mi < mcount; mi++ {
				mEntryOffset := methodsBase + mi*16
				if mEntryOffset+16 > len(fileBytes) {
					break
				}
				mnameOff := int(int32(binary.LittleEndian.Uint32(fileBytes[mEntryOffset : mEntryOffset+4])))
				mname, _ := getNameAt(mnameOff)
				if mname == "" {
					nameVaddr := roSec.Addr + uint64(typesRelOffset(typesFileOffset, mnameOff, roSec))
					mname, _ = getNameFromVaddr(nameVaddr)
				}

				ifn := int32(binary.LittleEndian.Uint32(fileBytes[mEntryOffset+8 : mEntryOffset+12]))
				tfn := int32(binary.LittleEndian.Uint32(fileBytes[mEntryOffset+12 : mEntryOffset+16]))

				exported := len(mname) > 0 && unicode.IsUpper(rune(mname[0]))
				info.Methods = append(info.Methods, MethodInfo{
					Name:     mname,
					Exported: exported,
					Ifn:      ifn,
					Tfn:      tfn,
				})
			}
			if isCustom {
				report.CustomMethods += len(info.Methods)
			}
		}

		if isCustom {
			report.CustomTypes++
		}

		if filter == "" || strings.Contains(strings.ToLower(typeName), strings.ToLower(filter)) {
			report.Types = append(report.Types, info)
		}
	}

	allStrings := extractPrintableStrings(roData, 6)
	sensitivePatterns := []string{
		"http://", "https://", "token", "Token", "secret", "Secret", "password", "Password",
		"manifest", "auth.", "api.", "privateKey", "PrivateKey", "Session", "Station",
	}

	seenHits := make(map[string]bool)
	for _, s := range allStrings {
		for _, pat := range sensitivePatterns {
			if strings.Contains(s, pat) && !seenHits[s] {
				seenHits[s] = true
				report.SensitiveHits = append(report.SensitiveHits, s)
				break
			}
		}
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Println("================================================================================")
	fmt.Println(" .rodata Go Metadata & Type Descriptors Audit Report")
	fmt.Println("================================================================================")
	fmt.Printf(" Binary:             %s\n", binPath)
	fmt.Printf(" .rodata Section:    0x%x bytes (%.2f MB)\n", report.RoDataSize, float64(report.RoDataSize)/(1024*1024))
	fmt.Printf(" Types in .typelink: %d total (%d custom/app types)\n", report.TotalTypes, report.CustomTypes)
	fmt.Printf(" Exposed Methods:    %d app methods found in .rodata\n", report.CustomMethods)
	fmt.Printf(" Exposed Structs:    %d structs with extracted field/tag definitions\n", report.CustomStructs)
	fmt.Printf(" Sensitive Hits:     %d strings matching credentials/endpoints in .rodata\n", len(report.SensitiveHits))
	fmt.Println("================================================================================")

	count := len(report.Types)
	if limit > 0 && limit < count {
		count = limit
	}

	fmt.Printf("\n[+] Displaying %d matching types (filter: %q):\n", count, filter)
	for i := 0; i < count; i++ {
		t := report.Types[i]
		customBadge := ""
		if t.IsCustom {
			customBadge = " [*CUSTOM*]"
		}
		fmt.Printf("\n  [%4d] %s (%s, %d bytes)%s\n", i+1, t.Name, t.Kind, t.Size, customBadge)
		if t.PkgPath != "" {
			fmt.Printf("         PkgPath: %s\n", t.PkgPath)
		}
		if showStructs && len(t.Fields) > 0 {
			fmt.Printf("         Fields (%d):\n", len(t.Fields))
			for _, f := range t.Fields {
				tagStr := ""
				if f.Tag != "" {
					tagStr = fmt.Sprintf(" `%s`", f.Tag)
				}
				fmt.Printf("           +0x%02x %s%s\n", f.Offset, f.Name, tagStr)
			}
		}
		if showMethods && len(t.Methods) > 0 {
			fmt.Printf("         Methods (%d):\n", len(t.Methods))
			for _, m := range t.Methods {
				fmt.Printf("           -> %s (ifn: 0x%x, tfn: 0x%x)\n", m.Name, m.Ifn, m.Tfn)
			}
		}
	}
	if len(report.Types) > count {
		fmt.Printf("\n  ... [%d more types omitted; use --limit 0 for full dump]\n", len(report.Types)-count)
	}

	if showStrings && len(report.SensitiveHits) > 0 {
		fmt.Printf("\n================================================================================\n")
		fmt.Printf(" .rodata String Inspection (%d potential sensitive hits):\n", len(report.SensitiveHits))
		fmt.Printf("================================================================================\n")
		displayCount := len(report.SensitiveHits)
		if displayCount > 30 {
			displayCount = 30
		}
		for i := 0; i < displayCount; i++ {
			fmt.Printf("  [%2d] %s\n", i+1, report.SensitiveHits[i])
		}
		if len(report.SensitiveHits) > 30 {
			fmt.Printf("  ... [%d more hits omitted]\n", len(report.SensitiveHits)-30)
		}
	}

	return nil
}

func typesRelOffset(baseOffset, off int, roSec *elf.Section) int {
	return off
}
