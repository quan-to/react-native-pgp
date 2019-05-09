package chevronwrap

import (
	"github.com/quan-to/chevron/chevronlib"
	"strings"
)

//export LoadKey
func LoadKey(keyData string) (loadedPrivateKeys int, err error) {
	return chevronlib.LoadKey(keyData)
}

//export UnlockKey
func UnlockKey(fingerprint, password string) (err error) {
	return chevronlib.UnlockKey(fingerprint, password)
}

//export VerifySignature
func VerifySignature(data []byte, signature string) (result bool, err error) {
	return chevronlib.VerifySignature(data, signature)
}

//export VerifyBase64DataSignature
func VerifyBase64DataSignature(b64data, signature string) (result bool, err error) {
	return chevronlib.VerifyBase64DataSignature(b64data, signature)
}

//export SignData
func SignData(data []byte, fingerprint string) (result string, err error) {
	return chevronlib.SignData(data, fingerprint)
}

//export SignBase64Data
func SignBase64Data(b64data, fingerprint string) (result string, err error) {
	return chevronlib.SignBase64Data(b64data, fingerprint)
}

//export GetKeyFingerprints
func GetKeyFingerprints(keyData string) (result string, err error) {
	r, e := chevronlib.GetKeyFingerprints(keyData)
	if len(r) > 0 {
		result = strings.Join(r, ",") // Go Mobile does not support string array as return, so we return a comma separated string
	}
	err = e
	return
}

//export ChangeKeyPassword
func ChangeKeyPassword(keyData, currentPassword, newPassword string) (newKeyData string, err error) {
	return chevronlib.ChangeKeyPassword(keyData, currentPassword, newPassword)
}

//export GetPublicKey
func GetPublicKey(fingerprint string) (keyData string, err error) {
	return chevronlib.GetPublicKey(fingerprint)
}

//export GenerateKey
func GenerateKey(password, identifier string, bits int) (result string, err error) {
	return chevronlib.GenerateKey(password, identifier, bits)
}
