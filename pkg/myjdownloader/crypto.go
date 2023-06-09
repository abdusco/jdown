package myjdownloader

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
)

type crypto struct {
	creds Credentials
}

func (c crypto) makeSecret(purpose string) []byte {
	hash := sha256.Sum256([]byte(strings.ToLower(c.creds.Email) + c.creds.Password + purpose))
	return hash[:]
}

func (c crypto) LoginSecret() []byte {
	return c.makeSecret("server")
}
func (c crypto) DeviceSecret() []byte {
	return c.makeSecret("device")
}

func (c crypto) Sign(key []byte, message []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c crypto) Encrypt(key []byte, message []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes long")
	}

	iv := key[:16]     // first half
	aesKey := key[16:] // second half

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	enc := cipher.NewCBCEncrypter(block, iv)

	padded := c.pad(message, enc.BlockSize())
	buf := make([]byte, len(padded))
	enc.CryptBlocks(buf, padded)
	return buf, nil
}

func (c crypto) Decrypt(key []byte, encrypted []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be at least 32 bytes")
	}
	iv := key[:16]     // first half
	aesKey := key[16:] // second half

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	dec := cipher.NewCBCDecrypter(block, iv)

	buf := make([]byte, len(encrypted))
	dec.CryptBlocks(buf, encrypted)
	buf = c.unpad(buf)

	return buf, nil
}

// pad pads a message using PKCS-7 scheme
func (c crypto) pad(message []byte, blockSize int) []byte {
	padding := blockSize - len(message)%blockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(message, pad...)
}

// unpad trims padding of a PKCS-5 encrypted text
func (c crypto) unpad(text []byte) []byte {
	// last byte gives the padding size
	padding := int(text[len(text)-1])
	return text[:len(text)-padding]
}
