package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

const vaultSentinelPlaintext = "LSS_VAULT_VERIFIED_2026"

// CredentialsHash computes SHA-256 of credentials joined by ":" separator.
// Matches the CLI's computation for tamper detection.
func CredentialsHash(sshUsername, sshPassword, encryptionPassword string) string {
	data := sshUsername + ":" + sshPassword + ":" + encryptionPassword
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// VaultEncrypt encrypts a value for vault storage using AES-256-GCM with the appKey.
// The vault password gates access (verified via sentinel), not encryption.
func VaultEncrypt(plaintext string, appKey []byte) (string, error) {
	return encryptAESGCM([]byte(plaintext), appKey)
}

// VaultDecrypt decrypts a vault-stored value using the appKey.
func VaultDecrypt(encrypted string, appKey []byte) (string, error) {
	plain, err := decryptAESGCM(encrypted, appKey)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// VaultCreateSentinel encrypts the known sentinel using a key derived from
// both the vault password and appKey. This proves the vault password is correct
// without storing it.
func VaultCreateSentinel(vaultPassword string, appKey []byte) (string, error) {
	combined := append([]byte(vaultPassword), appKey...)
	return encryptAESGCM([]byte(vaultSentinelPlaintext), combined)
}

// VaultVerifySentinel checks the vault password is correct by decrypting the sentinel.
func VaultVerifySentinel(sentinelEnc string, vaultPassword string, appKey []byte) bool {
	combined := append([]byte(vaultPassword), appKey...)
	plain, err := decryptAESGCM(sentinelEnc, combined)
	if err != nil {
		return false
	}
	return string(plain) == vaultSentinelPlaintext
}
