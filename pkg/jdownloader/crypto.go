package jdownloader

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
	creds       Credentials
	loginSecret [32]byte
}

func newCrypto(creds Credentials) crypto {
	c := crypto{
		creds: creds,
	}
	c.loginSecret = c.makeSecret("server")
	return c
}

func (c crypto) makeSecret(purpose string) [32]byte {
	return sha256.Sum256([]byte(strings.ToLower(c.creds.Email) + c.creds.Password + purpose))
}

// sign signs a message using HMAC-SHA256 scheme
func (c crypto) sign(message string) string {
	h := hmac.New(sha256.New, c.loginSecret[:])
	h.Write([]byte(message))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c crypto) decrypt(encrypted []byte) ([]byte, error) {
	aesKey := c.loginSecret[16:] // first half
	iv := c.loginSecret[:16]     // second half

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	buf := make([]byte, len(encrypted))
	cbc.CryptBlocks(buf, encrypted)
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
