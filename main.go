package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type session struct {
	// each of sending and receiving has it's own symmetric key
	// tx is the trasmit key, which we use to encrypt messages we're sending
	// rx is the receive key, which is used to decrypt received messages
	// our rx key is the client's tx key. and the client's rx is our tx
	rx, tx [32]byte
}

type handshakeReq struct {
	ClientPub string `json:"clientPub"` // base64 client public key
}
type handshakeResp struct {
	SessionId string `json:"sessionId"`
}

var (
	serverKxPublic, serverKxSecret [32]byte // Key exchange keys
	sessions                       sync.Map //string[int]=>session
)

// Step 1 generate our key exchange pair
// this is long term key exchange pair
// that uses X25519 to generate key-exchange keys
// that we will use in Diffie Hellman protocol
// this keypair can be reused for multiple clients as done in TLS 1.3 and in Signal
func keyExchangePair() {
	if _, err := rand.Read(serverKxSecret[:]); err != nil {
		log.Fatalf("generating random number failed %v", err)
	}
	curve25519.ScalarBaseMult(&serverKxPublic, &serverKxSecret)
}

// Step 2 advertise our exchange public key
func handlePub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, err := w.Write([]byte(base64.StdEncoding.EncodeToString(serverKxPublic[:])))
	if err != nil {
		http.Error(w, "public key publishing failure", http.StatusInternalServerError)

	}
}

// Step 3 receive client's exchange public key and generate session
func handleHandshake(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req handshakeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	clientPublicKey, err := base64.StdEncoding.DecodeString(req.ClientPub)
	if err != nil {
		http.Error(w, "bad client public key", http.StatusBadRequest)
		return
	}

	// derive shared secret and session key
	sharedSecret, err := curve25519.X25519(serverKxSecret[:], clientPublicKey[:])
	if err != nil {
		http.Error(w, "key exchange failed", http.StatusInternalServerError)
		return
	}

	// derive two AES-256 keys
	serverToClientKey := deriveSymmetricKey(sharedSecret[:], []byte("server-to-client")) // encryption
	clientToServerKey := deriveSymmetricKey(sharedSecret[:], []byte("client-to-server")) // decryption

	// create session
	sessionIdBytes := make([]byte, 16)
	if _, err := rand.Read(sessionIdBytes); err != nil {
		http.Error(w, "rand failed", http.StatusInternalServerError)
		return
	}
	sessionId := base64.StdEncoding.EncodeToString(sessionIdBytes)
	sessions.Store(sessionId, session{
		rx: clientToServerKey,
		tx: serverToClientKey,
	})

	resp := handshakeResp{
		SessionId: sessionId,
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, "send failed", http.StatusInternalServerError)
	}
}

// Step 4a receive encrypted message from client and send him my own encrypted msg
func handleReceive(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		http.Error(w, "missing session header", http.StatusBadRequest)
		return
	}
	sessRaw, ok := sessions.Load(sid)
	if !ok {
		fmt.Printf("couldn't find session %s", sid)
		http.Error(w, "unknown session", http.StatusBadRequest)
		return
	}
	sess := sessRaw.(session)

	// read the first 12 bytes for the iv
	iv := make([]byte, 12)
	if _, err := io.ReadFull(r.Body, iv); err != nil {
		http.Error(w, "error reading nonce", http.StatusBadRequest)
		return
	}

	// the rest of the bytes are the ciphertext
	ct, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	key := sess.rx // use the receive key because we want to decrypt what the client has sent
	block, err := aes.NewCipher(key[:])
	if err != nil {
		http.Error(w, "invalid AES key", http.StatusInternalServerError)
		return
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "invalid GCM", http.StatusInternalServerError)
		return
	}

	plain, err := aesGcm.Open(nil, iv, ct, nil)
	if err != nil {
		log.Default().Println(err.Error())
		http.Error(w, "AES-GCM auth failed", http.StatusUnauthorized)
		return
	}

	log.Printf("session id :%s  decrypted:\n%s", sid, plain)

	// -- now send our encrypted msg back to the client
	reply := []byte("server says hello!")
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		log.Default().Println(err.Error())
		http.Error(w, "generating nonce failed", http.StatusInternalServerError)
		return
	}
	key = sess.tx // use the trasmit key because we want to send
	block, err = aes.NewCipher(key[:])
	if err != nil {
		http.Error(w, "invalid AES key", http.StatusInternalServerError)
		return
	}
	aesGcm, err = cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "invalid GCM", http.StatusInternalServerError)
		return
	}
	replyCt := aesGcm.Seal(nil, nonce, reply, nil)

	// ---- raw response: IV || ciphertext ----
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(nonce)
	w.Write(replyCt)
}

func deriveSymmetricKey(sharedSecret []byte, info []byte) (out [32]byte) {
	// hash based key derivation function aka hkdf
	hkdfReader := hkdf.New(sha256.New, sharedSecret, make([]byte, 32), info)
	if _, err := io.ReadFull(hkdfReader, out[:]); err != nil {
		panic(err)
	}
	return
}

func withLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Default().Println(r.URL)
		next.ServeHTTP(w, r)
	})
}
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Id")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	keyExchangePair()
	mux := http.NewServeMux()

	mux.HandleFunc("/kx/pub", handlePub)
	mux.HandleFunc("/kx/handshake", handleHandshake)
	mux.HandleFunc("/kx/send", handleReceive)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", withLog(withCORS(mux))))
}
