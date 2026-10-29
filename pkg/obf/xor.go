package obf

// Obf encodes a plaintext string with an XOR mask for compile-time byte slices.
func Obf(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ (key + byte(i*37))
	}
	return out
}

// Deobf decodes an obfuscated byte slice using an XOR key and position offset.
func Deobf(data []byte, key byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ (key + byte(i*37))
	}
	return string(out)
}
