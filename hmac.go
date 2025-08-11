package main

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Determines if the MAC of a message is valid given a key
func ValidMac(message []byte, messageMAC []byte, key []byte) bool {
	// Hash message using the same key
	mac := hmac.New(sha256.New, key)
	mac.Write(message)          // Compute SHA256 hash of the received message
	expectedMAC := mac.Sum(nil) // Fetch the MAC of the message
	// Check if message MAC is equal to expected MAC
	return hmac.Equal(messageMAC, expectedMAC)
}

// Generates a HMAC given a key and message
func GenerateMac(message []byte, key []byte) []byte {
	// Hash message using key
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// Function that uses a HKDF to generate 20 32-byte keys to use with HMAC
func GenerateMacKeys(shared_secret []byte) ([20][]byte, error) {

	// generate 640 byte key (which we will split into 20 32-byte keys)
	key_array, err := hkdf.Key(sha256.New, shared_secret, nil, "", 640)
	if err != nil {
		fmt.Printf("key generation failed!\n")
		return [20][]byte{}, err
	}

	// split 640 byte key into 20 32-byte keys
	hmac_keys := [20][]byte{}
	for i := range 20 {
		hmac_keys[i] = key_array[i : i+32]
	}

	return hmac_keys, err
}
