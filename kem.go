package main

import (
	"crypto/mlkem"
)

func ServerKEM(encapsulation_key []byte) []byte {
	encapsulate_shared_secret, err := mlkem.NewEncapsulationKey1024(encapsulation_key)
	if err != nil {
		panic(err)
	}
	shared_secret, ciphertext := encapsulate_shared_secret.Encapsulate()
	_ = shared_secret // Has shared secret
	return ciphertext // The server needs the shared secret later on
}

// Creates shared secret key (but does it all in one function since we don't need to sign the encapsulated shared secret, in the middle)
func ClientKEM() []byte {
	// Client creates a key and sends encapsulation key to Receiver
	priv_decapsulation_key, err := mlkem.GenerateKey1024()
	if err != nil {
		panic(err)
	}
	pub_encapsulation_key := priv_decapsulation_key.EncapsulationKey().Bytes()

	// Receiver uses encapsulation key to encapsulate shared secret
	// Ciphertext from receiver sent to sender
	encapsulated_shared_secret := ServerKEM(pub_encapsulation_key)

	// Sender decapsulates shared secret from ciphertext
	shared_secret, err := priv_decapsulation_key.Decapsulate(encapsulated_shared_secret)

	// Receiver/Sender shares symmetric key
	return shared_secret
}

// Like ServerKEM, but also returns the shared_secret so Host 2 can save it for itself.
func InitServerKEM(encapsulation_key []byte) ([]byte, []byte) {
	encoded_encapsulation_key, err := mlkem.NewEncapsulationKey1024(encapsulation_key)
	if err != nil {
		panic(err)
	}
	shared_secret, encapsulated_shared_secret := encoded_encapsulation_key.Encapsulate()

	return encapsulated_shared_secret, shared_secret
}

// like CleintKEM, but returns the public and private encapsulation keys only
// We'll keep ClientKEM around because we'll need it for session resumption because we don't want to redo the entire handshake process.
func InitClientKEM() ([]byte, *mlkem.DecapsulationKey1024) {
	// Client creates a key and sends encapsulation key to Receiver
	priv_decapsulation_key, err := mlkem.GenerateKey1024()
	if err != nil {
		panic(err)
	}
	pub_encapsulation_key := priv_decapsulation_key.EncapsulationKey().Bytes()

	return pub_encapsulation_key, priv_decapsulation_key
}
