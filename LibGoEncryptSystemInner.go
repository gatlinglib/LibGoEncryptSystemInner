package LibGoEncryptSystemInner


import (
	iEncrypt "github.com/gatlinglib/LibGoEncryptSystemInner/internal"
)

func LGESI_Encrypt(text string) (string, error) {
	return iEncrypt.AES_Encrypt(text)
}
func LGESI_Decrypt(text string) (string, error) {
	return iEncrypt.AES_Decrypt(text)
}
