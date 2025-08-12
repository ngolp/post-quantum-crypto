# post-quantum-crypto

## General Information
1. This is an encryption scheme to send and receive data securely. We built it with post-quantum security in mind.
2. We use ML-KEM for asymmetric shared key establishment, ML-DSA for asymmetric digital signature authentication, AES256-CTR for symmetric encryption, and HMAC-SHA256 for symmetric authentication.
3. These algorithms were chosen to stay above an effective key size of 80 bits, even with Shor's algorithm and Grover's algorithm in effect.
4. After 20 messages have been sent, a new shared secret key will be established, mimicking ephemeral key usage.
5. We use a cryptographic HMAC ratchet to have both the sender and receiver generate 20 random HMAC keys at a time, never using the same HMAC key twice. Once the ratchet depletes of HMAC keys, a new ratchet of 20 HMAC keys is generated.
6. Rule #1 of cryptography is to never do it yourself! As such, we heavily use the Go crypto package.

## Usage

1. The entry.go file contains the logic for sending and receiving data between two hosts. This is handled with the independent Host 1 and Host 2 structs.

<img width="723" height="234" alt="image" src="https://github.com/user-attachments/assets/7ee78610-cb92-42c4-acbc-d6505d7681e2" />

2. The hosts will exchange messages as an array of strings, one string at a time. I use President Lincoln's Gettysburg Address as an example.

<img width="971" height="610" alt="image" src="https://github.com/user-attachments/assets/8b1597db-8c2d-413d-8f70-48f95a90b3ce" />

3. All the necessary files are included in this repository. You can either run using _go run ._ or using the included Go binary with _./post-quantum-crypto_

4. Once the program starts, it will display information to narrate the process of this cryptographic scheme. This first part displays the asymmetric portion of this cryptographic scheme, used to establish a shared secret key with ML-KEM and verify authenticity with ML-DSA.

<img width="1310" height="323" alt="image" src="https://github.com/user-attachments/assets/79d61d9e-1c52-451e-bf27-0a4dd36a7cb8" />

5. With a shared secret key established, we then move into symmetric cryptography with AES256-CTR and HMAC-SHA256 to encrypt, decrypt, and verify messages.

<img width="843" height="214" alt="image" src="https://github.com/user-attachments/assets/20822846-ccaa-4386-9e05-510c6cedd647" />

6. After 20 messages have been sent, the program establishes a new shared secret key with ML-KEM and ML-DSA. Additionally, the HMAC ratchet is depleted of HMAC keys, and the program generates a new ratchet of 20 HMAC keys.

<img width="630" height="306" alt="image" src="https://github.com/user-attachments/assets/19587a0e-c39b-4eeb-9f83-cd2f42df7412" />

## Authors
 - Nicholas Golparvar
 - Terry Weatherman
 - Alex Stacey 


