A simple frontend and backend that use X25519 key exchange to establish a bidirectional AEAD-secured symmetric channel. It uses cypto.subtle interface in the browser to protect against an attacker trying to extract the keys from the frontend's javascript. The secure channel uses to AES-GCM symmetric tx/rx keys for communication.

We are limited with the choice of algorithms to only the things that the crypt.suble api supports. So we can't use better crypto algorithms, or even quantum resistant lattice algorithms for encryption/decryption, sign/verify, and key exchange.

It's possible to use other algorithms, but then the keys would sit in the Javascript space, making them vulnerable for extraction by an attacker. So it's best to stick to what the crypto.sublte javascript api has since it doesn't store the keys in javascript.


### How to run the program
1. run `go run main.go`
2. open `frontend.html` in your browser
3. you should see messeges being printed to both the browser console and the server terminal. this are the encrypted/decrypted messages
