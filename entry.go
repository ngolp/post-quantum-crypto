package main

import (
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"slices"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// Not all of these fields will be used between Host 1 and 2, but this struct exists
// to show whether Host1 and Host2 handle/contain what data in the asymmetric portion
// of this cryptoscheme.
type Host struct {
	Public_signing_key                *mldsa44.PublicKey
	Private_signing_key               *mldsa44.PrivateKey
	Public_encapsulation_key          []byte
	Private_decapsulation_key         *mlkem.DecapsulationKey1024
	Encapsulated_shared_secret        []byte
	Signed_encapsulated_shared_secret []byte
	Shared_secret                     []byte
}

func main() {
	// Define plaintext messages to encrypt and decrypt
	// This large number of messages was chosen so that a new shared secret and ratchet will be made mid-communication
	message_arr := []string{
		"Four score and seven years ago",
		"Our fathers brought upon this continent",
		"A new nation, conceived in liberty",
		"And dedicated to the proposition that",
		"All men are created equal",
		"Now we are engaged in a great civil war",
		"Testing whether that nation, or any nation so conceived",
		"And so dedicated, can long endure",
		"We are met on a great battle field of that war",
		"We come to dedicate a portion of it, as a final resting place",
		"For those who died here, that the nation might live",
		"This we may, in all propriety do",
		"But, in a larger sense, we can not dedicate",
		"We can not consecrate we can not hallow, this ground The brave men",
		"Living and dead, who struggled here, have hallowed it",
		"Far above our poor power to add or detract. The world will little note",
		"Nor long remember what we say here",
		"While it can never forget what they did here",
		"It is rather for us, the living, we here be dedicated",
		"To the great task remaining before us that",
		"from these honored dead we take increased devotion",
		"to that cause for which they here, gave the last full measure",
		"of devotion that we here highly resolve these dead",
		"shall not have died in vain; that the nation",
		"shall have a new birth of freedom, and that government of the people",
		"by the people",
		"for the people",
		"shall not perish from the earth",
	}
	message_ctr := 0 // index of which message is currently being encrypted/decrypted

	// Create Host 1 and Host 2
	Host_1 := Host{}
	Host_2 := Host{}

	// Host 1 will generate its public encapsulation key and private decapsulation key
	fmt.Printf("Host 1 generates its public encapsulation and private decapsulation keys for ML-KEM\n\n")
	Host_1.Public_encapsulation_key, Host_1.Private_decapsulation_key = InitClientKEM()

	// Host 1 will provide its public_encapsulation_key to Host 2 so Host 2 may make an encapsulated shared secret
	fmt.Printf("Host 1 sends its public encapsulation key to Host 2, in which Host 2 develops a shared secret and encapsulates it\n\n")
	Host_2.Encapsulated_shared_secret, Host_2.Shared_secret = InitServerKEM(Host_1.Public_encapsulation_key)

	// Host 2 generates its public and private keys to use for ML-DSA signatures
	Host_2.Public_signing_key, Host_2.Private_signing_key = GenerateSigningKeyPair()
	fmt.Printf("Host 2 generates its public and private keys for ML-DSA signatures\n\n")

	// Host 2 will sign the encapsulated shared secret
	Host_2.Signed_encapsulated_shared_secret = ServerSignature(Host_2.Public_signing_key, Host_2.Private_signing_key, Host_2.Encapsulated_shared_secret)
	fmt.Printf("Host 2 signs the encapsulated shared secret\n")
	fmt.Printf("signed encapsulated shared secret: %s...\n\n", Host_2.Signed_encapsulated_shared_secret[:10])

	// encapsulated shared secret and signed encapsulated shared Secret sent to Host 1
	fmt.Printf("Host 2 sends the encapsulated shared secret and signed encapsulated shared secret to Host 1 for it to verify\n")
	Host_1.Encapsulated_shared_secret = Host_2.Encapsulated_shared_secret
	Host_1.Signed_encapsulated_shared_secret = Host_2.Signed_encapsulated_shared_secret

	// Host 1 verifies the signed encapsulated shared secret using Host 2's public key
	if !VerifySignature(Host_2.Public_signing_key, Host_1.Signed_encapsulated_shared_secret, Host_1.Encapsulated_shared_secret) {
		fmt.Println("Invalid signature!")
		return
	}
	fmt.Printf("Host 1 has verified the encapsulated shared secret!\n\n")

	fmt.Printf("Now, Host 1 must use its private decapsulation key to decapsulate the encapsulated shared secret\n")
	Host_1.Shared_secret, _ = Host_1.Private_decapsulation_key.Decapsulate(Host_1.Encapsulated_shared_secret)
	fmt.Printf("Host 1 has decapsulated the encapsulated shared secret! Now both Host 1 and Host 2 have a shared secret\n")

	//Now that both Host_1 and Host_2 have the same shared secret, we can defer to a single shared_secret
	if !slices.Equal(Host_1.Shared_secret, Host_2.Shared_secret) {
		fmt.Printf("SHARED SECRETS ARE UNEQUAL BETWEEN HOST 1 AND HOST 2\n")
		return
	}
	shared_secret := Host_1.Shared_secret

	// from that shared secret, Host 1 and Host 2 will generate a common set of keys to use in HMAC using an HKDF
	fmt.Printf("Host 1 and Host 2 will use the randomness of the shared_secret in an HKDF function to generate 20 keys to use in HMAC (also called a 'ratchet')\n")
	ratchet, _ := GenerateMacKeys(shared_secret)
	fmt.Printf("Ratchet has been generated!\n\n")

	// We now have a new shared secret so we can start encrypting for 20 messages
	fmt.Printf("------------------------------------------------------------------------------------------\n")
	for i := 0; i < 20; i++ {

		// if we have worked through all messages, break the loop
		if message_ctr == (len(message_arr)) {
			break
		}

		// make a 16 bytes for AES-CTR nonce. This nonce will be shared between Host 1 and Host 2, only be used for one message, and will not be used again.
		nonce := make([]byte, 16)
		rand.Read(nonce)
		fmt.Printf("Host 1 and Host 2 have created a nonce!\n\n")

		// make AES-CTR ciphertext
		fmt.Printf("Plaintext is encrypted using AES in CTR mode\n")
		ciphertext, _ := aes_encrypt(shared_secret, nonce, []byte(message_arr[message_ctr]))
		fmt.Printf(">>>This is my ciphertext: %s\n\n", ciphertext)

		// Calculate HMAC
		fmt.Printf("HMAC of ciphertext has been created\n")
		hmac := GenerateMac(ciphertext, ratchet[i])

		// Verify the HMAC
		if !ValidMac(ciphertext, hmac, ratchet[i]) {
			fmt.Printf("Invalid Hmac!\n")
			return
		}
		fmt.Printf("HMAC of ciphertext has been verified\n\n")

		// Decrypt the message using AES-CTR, and move onto the next message
		plaintext, _ := aes_decrypt(shared_secret, nonce, ciphertext)
		fmt.Printf("Ciphertext is decrypted using AES in CTR mode\n")
		fmt.Printf(">>>This is my plaintext: %s\n\n", plaintext)
		message_ctr++

		// once we use all keys in the ratchet, get a new shared_secret and ratchet
		if i == 19 {
			fmt.Printf("A ratchet has been depleted!\n")
			i = 0
			shared_secret = ClientKEM() // NOTE: we don't need to resign the new shared secret since we aim to mimic session resumption (NOT the full handshake)
			ratchet, _ = GenerateMacKeys(shared_secret)
			fmt.Printf("Host 1 and Host 2 create a shared secret key using ML-KEM\n")
			fmt.Printf("Shared secret: %s...\n", shared_secret[:10])
			fmt.Printf("A new ratchet has been generated for Host 1 and Host 2!\n\n")

		}
		fmt.Printf("------------------------------------------------------------------------------------------\n")
	}
}
