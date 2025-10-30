package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

func withLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Default().Println(r.URL)
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// origin := r.Header.Get("Origin")
		// if !isLocalhost(origin) { // only allow localhost
		// 	return
		// }
		w.Header().Set("Access-Control-Allow-Origin", "*") // I am opening an html file so the origin is null
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		allowedHeaders := "Content-Type, Authorization, X-Session-Id, X-Signature, X-Timestamp, X-Sequence"
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		w.Header().Set("Access-Control-Expose-Headers", allowedHeaders) // so client can see them otherwise they are hidden from client's javascript

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// validates session and counter
func withSessionValidator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/kx/handshake" || r.URL.Path == "/kx/pub" { // exclude the handshake, and public key broadcast
			next.ServeHTTP(w, r)
			return
		}
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
		rxSequenceHeader := r.Header.Get("X-Sequence")
		if rxSequenceHeader == "" {
			http.Error(w, "missing sequence header", http.StatusBadRequest)
			return
		}
		rxSequence, err := base64ToUint64(rxSequenceHeader)
		if err != nil {
			http.Error(w, "invalid sequence header", http.StatusBadRequest)
			return
		}
		sess := sessRaw.(session)
		if sess.rxCounter+1 != rxSequence {
			http.Error(w, fmt.Sprintf("invalid sequence. Expected %d, got %d",
				sess.rxCounter+1, rxSequence), http.StatusBadRequest)
			return
		}
		log.Default().Println("correct client sequence counter on ", r.URL.Path)

		sess.rxCounter = sess.rxCounter + 1 // this is the next expected client msg
		sess.txCounter = sess.txCounter + 1 // I will respond with this txCounter now
		sessions.Store(sess.id, sess)
		w.Header().Set("X-Sequence", uint64ToBase64(sess.txCounter))

		ctx := r.Context()
		ctx = context.WithValue(ctx, "my_session", sess)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func isLocalhost(origin string) bool {
	if origin == "" {
		return false
	}

	// Match http://localhost, https://localhost, http://127.0.0.1, etc. with any port
	localhostRegex := regexp.MustCompile(`^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$`)
	return localhostRegex.MatchString(origin)
}

// returns a 64 uint random value that we can use to start
// the sessions sequence counter, it has 32 bits of randomness
// leaving the other 32 for actual counting
func sequenceCounterInitValue() (uint64, error) {
	var b [4]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}
	return uint64(binary.BigEndian.Uint32(b[:])), nil
}

func base64ToUint64(s string) (uint64, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("wrong length: need 8 bytes, got %d", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

func uint64ToBase64(n uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return base64.StdEncoding.EncodeToString(b[:])
}
