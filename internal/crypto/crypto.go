package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const pskLen = 128

// printable ASCII: 0x21 '!' through 0x7E '~' (94 characters)
var printableChars = func() []byte {
	var b []byte
	for c := byte(0x21); c <= 0x7E; c++ {
		b = append(b, c)
	}
	return b
}()

// GeneratePSK returns a 128-character cryptographically random printable ASCII string.
func GeneratePSK() (string, error) {
	buf := make([]byte, pskLen)
	for i := range buf {
		var b [1]byte
		for {
			if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
				return "", fmt.Errorf("generate psk: %w", err)
			}
			// rejection sampling to avoid bias
			if int(b[0]) < len(printableChars)*(256/len(printableChars)) {
				buf[i] = printableChars[int(b[0])%len(printableChars)]
				break
			}
		}
	}
	return string(buf), nil
}

// EncryptPSK encrypts a raw PSK string for at-rest storage using appKey.
// Uses AES-256-GCM; key = SHA-256(appKey); output = base64(nonce+ciphertext+tag).
func EncryptPSK(psk string, appKey []byte) (string, error) {
	return encryptAESGCM([]byte(psk), appKey)
}

// DecryptPSK decrypts a stored PSK back to the raw string.
func DecryptPSK(encrypted string, appKey []byte) (string, error) {
	plain, err := decryptAESGCM(encrypted, appKey)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// DecryptNodePayload decrypts a base64-encoded node data blob using the raw PSK.
// key = SHA-256(psk); output = decrypted JSON bytes.
func DecryptNodePayload(dataB64 string, psk string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 12 {
		return nil, errors.New("payload too short")
	}

	key := deriveKey([]byte(psk))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonce := raw[:12]
	ciphertext := raw[12:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// encryptAESGCM encrypts plaintext using AES-256-GCM.
// key material is hashed with SHA-256; output = base64(nonce+ciphertext+tag).
func encryptAESGCM(plaintext, keyMaterial []byte) (string, error) {
	key := deriveKey(keyMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptAESGCM decrypts a base64(nonce+ciphertext+tag) blob.
func decryptAESGCM(encoded string, keyMaterial []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	key := deriveKey(keyMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// deriveKey returns SHA-256(input) as a 32-byte AES key.
func deriveKey(input []byte) []byte {
	h := sha256.Sum256(input)
	return h[:]
}
