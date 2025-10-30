package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type session struct {
	// each of sending and receiving has it's own symmetric key
	// tx is the trasmit key, which we use to encrypt messages we're sending
	// rx is the receive key, which is used to decrypt received messages
	// our rx key is the client's tx key. and the client's rx is our tx
	id                   string // putting the id again here for when I need to log
	rx, tx               [32]byte
	txCounter, rxCounter uint64 // prevents replay attacks by using bi-directional-sequence counting
}

type handshakeReq struct {
	ClientPub string `json:"clientPub"` // base64 client public key
}
type handshakeResp struct {
	SessionId     string `json:"sessionId"`
	ServerCounter string `json:"serverCounter"` // counts requests/responses server made
	ClientCounter string `json:"clientCounter"` // counts requests client made
}

var (
	serverKxPublic, serverKxSecret [32]byte          // Key exchange keys
	sessions                       sync.Map          //string[int]=>session
	serverSignPub                  ed25519.PublicKey //this would go with the CA certificate
	serverSignPriv                 ed25519.PrivateKey
)

// the signing keys help me prove to the client
// that the public keys I send are really from me
// and not from an imposter. This is important to
// do in the very first request when the client
// asks for the server's exchange public key
// because it's at that point that the attacker
// can impersonate the server and the client will
// not know it's talking to the real server or the attacker
// In this demo this key will be just provided to the client
// but in produciton it should
// come from a certificate which comes from
// a certificate authrority like "Let's Encrypt"
func initSigningKeys() {
	// uncomment to generate real keys
	// pub, priv, err := ed25519.GenerateKey(rand.Reader)
	// if err != nil {
	// 	panic(err)
	// }

	// we just save hardcode the keys for the demo, in reality you want the client to get
	// the signature verification public key from a Certificate.
	//  and the private key should be kept securliy outside the sourecode.
	pub, _ := base64.StdEncoding.DecodeString("W57lhSShASDfTDYPQpGpkJnbEAf84QtrGIZWtvi2+rk=")
	priv, _ := base64.StdEncoding.DecodeString("Pl1iDxGX+GGDMAvp3L5fctuM+as+9cVjRtQIWF4PduZbnuWFJKEBIN9MNg9CkamQmdsQB/zhC2sYhla2+Lb6uQ==")
	serverSignPub = pub
	serverSignPriv = priv
}

// Step 1 generate our key exchange pair
// this is long term key exchange pair
// that uses X25519 to generate key-exchange keys
// that we will use in Diffie Hellman protocol
// this keypair can be reused for multiple clients as done in TLS 1.3 and in Signal
func initKeyExchangePair() {
	if _, err := rand.Read(serverKxSecret[:]); err != nil {
		log.Fatalf("generating random number failed %v", err)
	}
	curve25519.ScalarBaseMult(&serverKxPublic, &serverKxSecret)
}

// Step 2 advertise our exchange public key
func handlePub(w http.ResponseWriter, r *http.Request) {
	keyExchangePublicKey := []byte(base64.StdEncoding.EncodeToString(serverKxPublic[:]))
	timestamp := time.Now().UTC().Format(time.RFC3339)
	contentType := "text/plain"

	// we sign both the timestamp and the exchange public key
	signatureData := fmt.Sprintf("%s\n%s\n%s", contentType, timestamp, keyExchangePublicKey)
	signature := ed25519.Sign(serverSignPriv, []byte(signatureData))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Timestamp", timestamp)
	w.Header().Set("X-Signature", signatureBase64)

	_, err := w.Write(keyExchangePublicKey)
	if err != nil {
		http.Error(w, "public key publishing failure", http.StatusInternalServerError)
		return
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
	// create sequnece counters, 4 byte integers for the random. leaving 4 other byes for counting
	txCounter, err := sequenceCounterInitValue()
	if err != nil {
		http.Error(w, "rand failed", http.StatusInternalServerError)
		return
	}
	rxCounter, err := sequenceCounterInitValue()
	if err != nil {
		http.Error(w, "rand failed", http.StatusInternalServerError)
		return
	}

	sessionId := base64.StdEncoding.EncodeToString(sessionIdBytes)
	sessions.Store(sessionId, session{
		id:        sessionId,
		rx:        clientToServerKey,
		tx:        serverToClientKey,
		txCounter: txCounter,
		rxCounter: rxCounter,
	})

	resp := handshakeResp{
		SessionId:     sessionId,
		ClientCounter: uint64ToBase64(rxCounter),
		ServerCounter: uint64ToBase64(txCounter),
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
	sessRaw := r.Context().Value("my_session")
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

	log.Printf("session id :%s  decrypted:\n%s", sess.id, plain)

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

func main() {
	initSigningKeys()
	initKeyExchangePair()
	mux := http.NewServeMux()

	mux.HandleFunc("/kx/pub", handlePub)
	mux.HandleFunc("/kx/handshake", handleHandshake)
	mux.HandleFunc("/kx/send", handleReceive)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", withLog(withCORS(withSessionValidator(mux)))))
}
