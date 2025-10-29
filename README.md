# A Simple yet secure api
A simple frontend and backend that use X25519 key exchange to establish a bidirectional AEAD-secured symmetric channel. It uses cypto.subtle interface in the browser to protect against an attacker trying to extract the keys from the frontend's javascript. The secure channel uses to AES-GCM symmetric tx/rx keys for communication.

NOTE: the steps in the code assume that the signature key has already been verfied

## Algorithms choice
We are limited with the choice of algorithms to only the things that the crypt.suble api supports. So we can't use better crypto algorithms, or even quantum resistant lattice algorithms for encryption/decryption, sign/verify, and key exchange.

It's possible to use other algorithms, but then the keys would sit in the Javascript space, making them vulnerable for extraction by an attacker. So it's best to stick to what the crypto.sublte javascript api has since it doesn't store the keys in javascript.

The best we currently have are the X25519 for key exchange, HKDF for transforming the shared secret into an AES-GCM symmetric key, and finally Ed25519 for signing and verification


## How to run the program
run go run main.go
open frontend.html in your browser
you should see messeges being printed to both the browser console and the server terminal. this are the encrypted/decrypted messages.


## Why is this api secure?
There are several security measures and here they are:
| Threat                                 | Protection mechanism                                     | Result                                                                |
| -------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------- |
| **Eavesdropping**                      | AES-GCM encryption with session keys derived from X25519 | Attacker learns nothing about message contents.                       |
| **Tampering / modification**           | AES-GCM AEAD tags                                        | Any change in ciphertext causes decryption to fail.                   |
| **MITM injection during key exchange** | Ed25519 signature over ephemeral pubkey                  | Client detects forged or modified public key.                         |
| **Replay attacks**                     | Timestamp in signed header + session keys                | Stale signed messages (old `/kx/pub`) are rejected.                   |
| **Server impersonation**               | CA-signed Ed25519 key(in the demo, the signature public keys is just provided to the client)                                     | Client knows it’s talking to the real server.                         |
| **Key compromise**                     | Ephemeral X25519 + per-session AES keys                  | Forward secrecy: past sessions stay safe even if long-term key leaks. |
| **Message authenticity**               | Ed25519 signature + AES-GCM authentication               | Client can verify every message truly came from the server.           |
| **Message integrity**                  | AES-GCM tag + signature coverage                         | Bit-flips or dropped data are detected immediately.                   |
