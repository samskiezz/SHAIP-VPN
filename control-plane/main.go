// Command control-plane implements PQANON-CP/1: the REST API for nodes,
// sessions, routing, settings, auth, and the signed CRL (§14).
//
// Storage selects automatically: if DATABASE_URL is set it uses Postgres
// (db/schema.sql), otherwise an in-memory store so the server boots standalone.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	addr := envOr("LISTEN_ADDR", ":8080")

	store, label := openStore()
	defer store.Close()

	tokens, err := NewTokenSigner(24 * time.Hour)
	if err != nil {
		log.Fatalf("token signer: %v", err)
	}
	crlPub, crlPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("crl key: %v", err)
	}

	srv := &Server{store: store, tokens: tokens, crlPub: crlPub, crlPriv: crlPriv}

	log.Printf("PQANON-CP/1 control plane listening on %s (store: %s)", addr, label)
	srvHTTP := &http.Server{
		Addr:              addr,
		Handler:           routes(srv, label),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srvHTTP.ListenAndServe())
}

// routes builds the HTTP handler. Extracted from main so tests can exercise
// the real router, middleware stack, and auth group.
func routes(srv *Server, label string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(corsMiddleware)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "store": label})
	})

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/register", srv.handleRegister)
		r.Post("/auth/login", srv.handleLogin)
		r.Get("/crl", srv.handleCRL) // tunnel servers fetch this unauthenticated

		r.Group(func(r chi.Router) {
			r.Use(srv.authMiddleware)
			r.Get("/nodes", srv.handleListNodes)
			r.Post("/nodes", srv.handleCreateNode)
			r.Delete("/nodes/{id}", srv.handleDeleteNode)
			r.Get("/connections", srv.handleListConnections)
			r.Delete("/connections/{id}", srv.handleDisconnect)
			r.Get("/mixnet", srv.handleMixnetStatus)
			r.Get("/dashboard", srv.handleDashboard)
			r.Get("/stats", srv.handleStats)
			r.Get("/me", srv.handleMe)
			r.Get("/routing", srv.handleListRouting)
			r.Post("/routing", srv.handleCreateRouting)
			r.Delete("/routing/{id}", srv.handleDeleteRouting)
			r.Get("/settings", srv.handleGetSettings)
			r.Put("/settings", srv.handleUpdateSettings)
		})
	})
	return r
}

func openStore() (Store, string) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		mem := NewMemStore()
		mem.SeedDemo()
		return mem, "memory"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pg, err := NewPgStore(ctx, url)
	if err != nil {
		log.Printf("postgres unavailable (%v); falling back to in-memory store", err)
		mem := NewMemStore()
		mem.SeedDemo()
		return mem, "memory"
	}
	return pg, "postgres"
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", envOr("CORS_ORIGIN", "*"))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
