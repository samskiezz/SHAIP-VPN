//go:build js && wasm

package main

// The control plane compiled to WebAssembly, for the hosted web preview: the
// same handlers, store, crypto and privacy rules as the server, running in the
// visitor's browser tab with the in-memory store. Nothing is seeded (no demo
// nodes or accounts) and nothing leaves the tab. The page calls
// pqanonAPI(method, path, authorization, body) instead of the network.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"
	"syscall/js"
	"time"
)

func main() {
	log.SetOutput(&redactingWriter{w: logDiscard{}})
	srv, err := newPreviewServer()
	if err != nil {
		js.Global().Set("pqanonAPIError", err.Error())
		return
	}
	h := routes(srv, "memory (this browser tab)")
	js.Global().Set("pqanonAPI", js.FuncOf(func(_ js.Value, args []js.Value) any {
		method, path, auth, body := args[0].String(), args[1].String(), args[2].String(), args[3].String()
		return newPromise(func() (any, error) {
			req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return map[string]any{"status": rec.Code, "body": rec.Body.String()}, nil
		})
	}))
	js.Global().Call("dispatchEvent", js.Global().Get("Event").New("pqanon-ready"))
	select {}
}

func newPreviewServer() (*Server, error) {
	tokens, err := NewTokenSigner(24 * time.Hour)
	if err != nil {
		return nil, err
	}
	keys := make([]ed25519.PrivateKey, 4)
	pubs := make([]ed25519.PublicKey, 4)
	for i := range keys {
		pubs[i], keys[i], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	mint, err := NewMint("", defaultDenominations())
	if err != nil {
		return nil, err
	}
	return &Server{
		store: NewMemStore(), tokens: tokens,
		crlPub: pubs[0], crlSigner: keys[0],
		enrollSigner: keys[1], enrollPub: pubs[1],
		deviceCASigner: keys[2], deviceCAPub: pubs[2],
		stake:     defaultStakeParams(),
		directory: &DirectoryAuthority{Name: "preview", Signer: keys[3], Pub: pubs[3]},
		mint:      mint, rails: map[string]PaymentRail{"dev": NewDevRail()}, defaultRail: "dev",
	}, nil
}

// newPromise runs f off the JS event loop and settles a Promise with its result.
func newPromise(f func() (any, error)) js.Value {
	var handler js.Func
	handler = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			defer handler.Release()
			v, err := f()
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(js.ValueOf(v))
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

type logDiscard struct{}

func (logDiscard) Write(p []byte) (int, error) { return len(p), nil }

var _ http.Handler = http.NotFoundHandler()
