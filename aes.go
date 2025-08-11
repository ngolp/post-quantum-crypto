package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func aes_encrypt(key []byte, nonce []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		fmt.Println("Must usea 256 bit key!")
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aes_ctr := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plaintext))
	aes_ctr.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func aes_decrypt(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		fmt.Println("Must use a 256 bit key!")
		return nil, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aes_ctr := cipher.NewCTR(block, nonce)
	plaintext := make([]byte, len(ciphertext))
	aes_ctr.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil

}
