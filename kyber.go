package main

import (
	"crypto"
	"crypto/rand"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// Verifies the server's signature is correct
func VerifySignature(public_signing_key *mldsa44.PublicKey, signature []byte, message []byte) bool {
	return public_signing_key.Scheme().Verify(public_signing_key, message, signature, nil)
}

// Sends the signature and public signing key
func ServerSignature(public_signing_key *mldsa44.PublicKey, private_signing_key *mldsa44.PrivateKey, shared_secret []byte) []byte {

	message := shared_secret
	signature, err := private_signing_key.Sign(rand.Reader, message, crypto.Hash(0)) // TODO: Check hash
	if err != nil {
		panic(err)
	}
	return signature
}

func GenerateSigningKeyPair() (public_key *mldsa44.PublicKey, private_key *mldsa44.PrivateKey) {
	public_signing_key, private_signing_key, _ := mldsa44.GenerateKey(rand.Reader)
	return public_signing_key, private_signing_key
}
