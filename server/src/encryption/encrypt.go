package encryption

import (
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

func Encrypt(key, plaintextMsg []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Generate a new nonce for this encryption.
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the message and append the nonce and the ciphertext.
	ciphertext := aead.Seal(nonce, nonce, plaintextMsg, nil)
	return ciphertext, nil
}
