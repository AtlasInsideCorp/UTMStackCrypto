package blind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

func Encrypt(key string, plain string) (string, error) {
	plainBytes := []byte(plain)

	block, blockErr := aes.NewCipher([]byte(key))
	if blockErr != nil {
		return "", blockErr
	}

	aesGCM, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return "", gcmErr
	}

	nonce := make([]byte, aesGCM.NonceSize())

	encrypted := aesGCM.Seal(nonce, nonce, plainBytes, nil)

	return fmt.Sprintf("%x", encrypted), nil
}

func GenerateCryptoKey(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return string(bytes), nil
}

func Decrypt(keySt string, encrypted string) (string, error) {
	key := []byte(keySt)
	enc, _ := hex.DecodeString(encrypted)

	block, ncErr := aes.NewCipher(key)
	if ncErr != nil {
		return "", ncErr
	}

	aesGCM, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return "", gcmErr
	}

	nonceSize := aesGCM.NonceSize()

	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, openErr := aesGCM.Open(nil, nonce, ciphertext, nil)
	if openErr != nil {
		return "", openErr
	}

	return string(plaintext), nil
}

func Encrypt16(key []byte, message string) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Decrypt16(key []byte, message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}
