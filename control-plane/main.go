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
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	addr := envOr("LISTEN_ADDR", ":8080")

	store, label := openStore()
	defer store.Close()

	tokens, err := openTokenSigner(24 * time.Hour)
	if err != nil {
		log.Fatalf("token signer: %v", err)
	}
	crlPub, crlPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("crl key: %v", err)
	}

	mint, err := NewMint(os.Getenv("PAY_KEY_DIR"), defaultDenominations())
	if err != nil {
		log.Fatalf("e-cash mint: %v", err)
	}
	rails, defaultRail := buildRails()

	srv := &Server{
		store: store, tokens: tokens, crlPub: crlPub, crlPriv: crlPriv,
		mint: mint, rails: rails, defaultRail: defaultRail,
		devSettle: os.Getenv("PAY_DEV_SETTLE") == "1",
	}
	if srv.devSettle {
		log.Printf("WARNING: PAY_DEV_SETTLE enabled — /api/pay/dev/settle will mark orders paid without a chain; never set this in production")
	}

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
	r.Use(metricsMiddleware)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "store": label})
	})
	r.Get("/metrics", handleMetrics) // Prometheus scrape target

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/register", srv.handleRegister)
		r.Post("/auth/login", srv.handleLogin)
		r.Get("/crl", srv.handleCRL)                   // tunnel servers fetch this unauthenticated
		r.Get("/public/status", srv.handlePublicStatus) // status pages / uptime monitors

		// Untraceable payments (§20) — deliberately identity-free, so no auth.
		r.Get("/pay/denominations", srv.handleDenominations)
		r.Post("/pay/order", srv.handleCreateOrder)
		r.Get("/pay/order/{id}", srv.handleOrderStatus)
		r.Post("/pay/collect", srv.handleCollect)
		r.Post("/pay/redeem", srv.handleRedeem)
		r.Post("/pay/dev/settle", srv.handleDevSettle) // gated by PAY_DEV_SETTLE

		r.Group(func(r chi.Router) {
			r.Use(srv.authMiddleware)
			r.Get("/nodes", srv.handleListNodes)
			r.Post("/nodes", srv.handleCreateNode)
			r.Get("/nodes/{id}", srv.handleGetNode)
			r.Delete("/nodes/{id}", srv.handleDeleteNode)
			r.Get("/connections", srv.handleListConnections)
			r.Get("/connections/{id}", srv.handleGetConnection)
			r.Delete("/connections/{id}", srv.handleDisconnect)
			r.Get("/mixnet", srv.handleMixnetStatus)
			r.Get("/dashboard", srv.handleDashboard)
			r.Get("/stats", srv.handleStats)
			r.Get("/admin/stats", srv.handleAdminStats)
			r.Get("/me", srv.handleMe)
			r.Get("/routing", srv.handleListRouting)
			r.Post("/routing", srv.handleCreateRouting)
			r.Delete("/routing/{id}", srv.handleDeleteRouting)
			r.Get("/settings", srv.handleGetSettings)
			r.Put("/settings", srv.handleUpdateSettings)
			r.Get("/apikeys", srv.handleListAPIKeys)
			r.Post("/apikeys", srv.handleCreateAPIKey)
			r.Delete("/apikeys/{id}", srv.handleDeleteAPIKey)
			r.Get("/audit", srv.handleListAudit)
		})
	})
	return r
}

// openTokenSigner loads a stable token signing key from TOKEN_SIGNING_KEY
// (base64 of a 32-byte Ed25519 seed) so tokens survive restarts and are shared
// across replicas. Without it, an ephemeral key is generated and a warning is
// logged — fine for dev, not for production.
func openTokenSigner(ttl time.Duration) (*TokenSigner, error) {
	if v := os.Getenv("TOKEN_SIGNING_KEY"); v != "" {
		seed, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("TOKEN_SIGNING_KEY must be base64: %w", err)
		}
		return NewTokenSignerWithSeed(ttl, seed)
	}
	log.Printf("WARNING: TOKEN_SIGNING_KEY not set — using an ephemeral key; tokens will not survive a restart. Generate one with: openssl rand -base64 32")
	return NewTokenSigner(ttl)
}

// buildRails assembles the available payment backends. The dev rail is always
// present (for local/CI; its settle endpoint is separately gated). Monero and
// BTCPay turn on when configured. The default rail is Monero if available, else
// BTCPay, else dev.
func buildRails() (map[string]PaymentRail, string) {
	rails := map[string]PaymentRail{"dev": NewDevRail()}
	defaultRail := "dev"

	if url := os.Getenv("MONERO_WALLET_RPC"); url != "" {
		account := uint32(atoiOr("MONERO_ACCOUNT_INDEX", 0))
		minConf := atoiOr("MONERO_MIN_CONF", 10)
		rails["monero"] = NewMoneroRail(url, account, minConf,
			os.Getenv("MONERO_RPC_USER"), os.Getenv("MONERO_RPC_PASS"))
		defaultRail = "monero"
		log.Printf("payments: Monero rail via %s (account %d, min %d confirmations)", url, account, minConf)
	}
	if url := os.Getenv("BTCPAY_URL"); url != "" {
		store := os.Getenv("BTCPAY_STORE_ID")
		key := os.Getenv("BTCPAY_API_KEY")
		if store == "" || key == "" {
			log.Printf("payments: BTCPAY_URL set but BTCPAY_STORE_ID/BTCPAY_API_KEY missing; BTCPay rail disabled")
		} else {
			rails["btcpay"] = NewBtcpayRail(url, store, key)
			if defaultRail == "dev" {
				defaultRail = "btcpay"
			}
			log.Printf("payments: BTCPay rail (Bitcoin + Lightning) via %s", url)
		}
	}
	if defaultRail == "dev" {
		log.Printf("payments: DEV rail only (no chain). Set MONERO_WALLET_RPC and/or BTCPAY_URL for real payments.")
	}
	return rails, defaultRail
}

func atoiOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
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
