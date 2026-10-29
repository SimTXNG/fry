package assets

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// DeriveKey derives a deterministic 32-byte AES-256 key using a multi-seed mixer.
func DeriveKey() [32]byte {
	seedA := []byte{0x73, 0x69, 0x6d, 0x74, 0x78, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x72} // "simtx-transmitter"
	seedB := []byte{0x2e, 0x61, 0x73, 0x73, 0x65, 0x74, 0x2d, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x2d, 0x76, 0x31}       // ".asset-packer-v1"
	seedC := []byte{0x9c, 0x31, 0x88, 0x4f, 0x1d, 0x7e, 0x5b, 0xa2, 0x44, 0x60, 0xef, 0x03, 0x12, 0x8d, 0x93, 0xaa}

	h := sha256.New()
	h.Write(seedA)
	h.Write(seedB)
	h.Write(seedC)

	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// Pack traverses inputDir, zips its contents, encrypts with AES-256-GCM using key,
// and writes the result to outputFile.
func Pack(inputDir, outputFile string, key [32]byte) error {
	fi, err := os.Stat(inputDir)
	if err != nil {
		return fmt.Errorf("stat input dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", inputDir)
	}

	zipBuf := new(bytes.Buffer)
	zw := zip.NewWriter(zipBuf)

	totalFiles := 0
	var uncompressedBytes int64

	err = filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(inputDir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate

		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		n, err := io.Copy(w, f)
		if err != nil {
			return err
		}
		uncompressedBytes += n
		totalFiles++
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking input dir: %w", err)
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("closing zip writer: %w", err)
	}

	plainZip := zipBuf.Bytes()

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plainZip, nil)
	encryptedPayload := append(nonce, ciphertext...)

	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	if err := os.WriteFile(outputFile, encryptedPayload, 0644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	reduction := float64(len(plainZip)) / float64(uncompressedBytes) * 100
	fmt.Printf("fry pack: encrypted %d files (%.2f MB raw -> %.2f MB enc, %.1f%% of raw) -> %s\n",
		totalFiles, float64(uncompressedBytes)/(1024*1024), float64(len(encryptedPayload))/(1024*1024), reduction, outputFile)
	return nil
}

// Decrypt decrypts an AES-256-GCM encrypted payload and returns a *zip.Reader as fs.FS.
func Decrypt(encrypted []byte, key [32]byte) (fs.FS, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted payload too short (%d bytes)", len(encrypted))
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("asset decryption failed: %w", err)
	}

	readerAt := bytes.NewReader(plaintext)
	zipReader, err := zip.NewReader(readerAt, int64(len(plaintext)))
	if err != nil {
		return nil, fmt.Errorf("invalid zip archive: %w", err)
	}
	return zipReader, nil
}
