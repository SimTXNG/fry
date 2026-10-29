package fry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestObfDeobf(t *testing.T) {
	cases := []string{
		"https://manifest.simtx.net/version",
		"https://auth.simtx.net",
		"secret_token_abc_123",
		"",
	}

	for _, c := range cases {
		key := byte(0x42)
		enc := Obf(c, key)
		if c != "" && string(enc) == c {
			t.Errorf("Obf did not scramble string: %s", c)
		}
		dec := Deobf(enc, key)
		if dec != c {
			t.Errorf("Deobf = %q, want %q", dec, c)
		}
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	k1 := DeriveKey()
	k2 := DeriveKey()
	if k1 != k2 {
		t.Fatal("DeriveKey is non-deterministic")
	}
}

func TestPackAndDecrypt(t *testing.T) {
	tmpDir := t.TempDir()
	inDir := filepath.Join(tmpDir, "dist")
	if err := os.MkdirAll(filepath.Join(inDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(inDir, "index.html"), []byte("<h1>Hello</h1>"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inDir, "sub", "test.js"), []byte("console.log(1);"), 0644); err != nil {
		t.Fatal(err)
	}

	outFile := filepath.Join(tmpDir, "assets.enc")
	if err := PackAssets(inDir, outFile); err != nil {
		t.Fatalf("PackAssets failed: %v", err)
	}

	encData, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	fsys, err := DecryptAssets(encData)
	if err != nil {
		t.Fatalf("DecryptAssets failed: %v", err)
	}

	idxFile, err := fsys.Open("index.html")
	if err != nil {
		t.Fatalf("Open index.html failed: %v", err)
	}
	idxFile.Close()

	subFile, err := fsys.Open("sub/test.js")
	if err != nil {
		t.Fatalf("Open sub/test.js failed: %v", err)
	}
	subFile.Close()
}
