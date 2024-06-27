package encryption

import (
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
)

func Decrypt(key, ciphertextMsg []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	tagSize := aead.Overhead()
	if len(ciphertextMsg) < nonceSize+tagSize {
		return nil, errors.New("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext, tag := ciphertextMsg[:nonceSize], ciphertextMsg[nonceSize:len(ciphertextMsg)-tagSize], ciphertextMsg[len(ciphertextMsg)-tagSize:]

	return aead.Open(nil, nonce, append(ciphertext, tag...), nil)
}
