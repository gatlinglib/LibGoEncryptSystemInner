package iEncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/pbkdf2"
)

// type cDatabaseModelWrapper struct {
// }
var G_Key = ""

func init() {
	strTmp := fmt.Sprintf("%.5f", math.E)[2:]
	strTmp += fmt.Sprintf("%.5f", math.Phi)[2:]
	strTmp += fmt.Sprintf("%.6f", math.Pi)[2:]

	G_Key = strTmp
}

func AES_Encrypt(text string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(G_Key), salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	encryptedText := make([]byte, len(text))
	stream.XORKeyStream(encryptedText, []byte(text))

	combined := append(salt, iv...)
	combined = append(combined, encryptedText...)
	return base64.StdEncoding.EncodeToString(combined), nil
}
func AES_Decrypt(text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}

	salt := data[:16]
	iv := data[16 : 16+aes.BlockSize]
	encryptedTextBytes := data[16+aes.BlockSize:]

	key := pbkdf2.Key([]byte(G_Key), salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	plainText := make([]byte, len(encryptedTextBytes))
	stream.XORKeyStream(plainText, encryptedTextBytes)
	return string(plainText), nil
}
