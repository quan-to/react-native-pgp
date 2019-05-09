package chevronwrap

import (
	"github.com/quan-to/chevron/chevronlib"
	"strings"
)

// LoadKey loads a key to in-memory storage
func LoadKey(keyData string) (loadedPrivateKeys int, err error) {
	return chevronlib.LoadKey(keyData)
}

// UnlockKey unlocks a private key on in-memory storage
func UnlockKey(fingerprint, password string) (err error) {
	return chevronlib.UnlockKey(fingerprint, password)
}

// VerifySignature verifies a signature using cached public key
func VerifySignature(data []byte, signature string) (result bool, err error) {
	return chevronlib.VerifySignature(data, signature)
}

// VerifyBase64DataSignature verifies a signature using cached public key
// b64data is a raw binary in base64 format
func VerifyBase64DataSignature(b64data, signature string) (result bool, err error) {
	return chevronlib.VerifyBase64DataSignature(b64data, signature)
}

// SignData signs data using a unlocked in-memory private key
func SignData(data []byte, fingerprint string) (result string, err error) {
	return chevronlib.SignData(data, fingerprint)
}

// SignBase64Data signs data using a unlocked in-memory private key
// b64data is a raw binary in base64 format
func SignBase64Data(b64data, fingerprint string) (result string, err error) {
	return chevronlib.SignBase64Data(b64data, fingerprint)
}

// GetKeyFingerprints returns fingerprints of the keys inside the armored keychain
func GetKeyFingerprints(keyData string) (result string, err error) {
	r, e := chevronlib.GetKeyFingerprints(keyData)
	if len(r) > 0 {
		result = strings.Join(r, ",") // Go Mobile does not support string array as return, so we return a comma separated string
	}
	err = e
	return
}

// ChangeKeyPassword Loads, unlock and saves a new private key with a new password
func ChangeKeyPassword(keyData, currentPassword, newPassword string) (newKeyData string, err error) {
	return chevronlib.ChangeKeyPassword(keyData, currentPassword, newPassword)
}

// GetPublicKey Returns a public key from a loaded key
func GetPublicKey(fingerprint string) (keyData string, err error) {
	return chevronlib.GetPublicKey(fingerprint)
}

// GenerateKey Generates a new PGP Key with the specified parameters
func GenerateKey(password, identifier string, bits int) (result string, err error) {
	return chevronlib.GenerateKey(password, identifier, bits)
}
