package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Shared encryption key - In production, use environment variable or key management service.
// This must be exactly 32 bytes for AES-256.
const encryptionKey = "0123456789ABCDEF0123456789ABCDEF"

// EncryptMessage encrypts a message using AES-256-GCM
func EncryptMessage(plaintext string) (string, error) {
	key := []byte(encryptionKey)
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	// Create a nonce (GCM recommends 12 bytes)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	
	// Encrypt the data
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	
	// Return base64 encoded ciphertext
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a message using AES-256-GCM
func DecryptMessage(ciphertextBase64 string) (string, error) {
	key := []byte(encryptionKey)
	
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	
	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	
	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	
	return string(plaintext), nil
}
