// Command control-plane implements PQANON-CP/1: the REST API for accounts,
// devices, nodes, payments, staking, and the signed CRL (§14).
//
// It keeps nothing that identifies a customer (docs/privacy-policy.md):
// accounts are random numbers, requests are not logged, and no address is
// stored or written to a log.
//
// Storage selects automatically: if DATABASE_URL is set it uses Postgres
// (db/schema.sql), otherwise an in-memory store so the server boots standalone.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"pqanon/control-plane/keystore"
)

func main() {
	// Before anything can log: every line passes through the address redactor.
	log.SetOutput(&redactingWriter{w: os.Stderr})

	addr := envOr("LISTEN_ADDR", ":8080")

	store, label := openStore()
	defer store.Close()

	// Signing keys: each one may be a key file, an env seed, or an HSM key (see
	// keys.go and the keystore package).
	tokenKey, tokenSrc, err := resolveSigner("token", "TOKEN_SIGNER", "TOKEN_SIGNING_KEY")
	if err != nil {
		log.Fatalf("token signer: %v", err)
	}
	tokens, err := NewTokenSignerFromSigner(24*time.Hour, tokenKey)
	if err != nil {
		log.Fatalf("token signer: %v", err)
	}
	crlKey, crlSrc, err := resolveSigner("crl", "CRL_SIGNER", "")
	if err != nil {
		log.Fatalf("crl signer: %v", err)
	}
	crlPub, err := keystore.Ed25519Public(crlKey)
	if err != nil {
		log.Fatalf("crl signer: %v", err)
	}
	enrollKey, enrollSrc, err := resolveSigner("enroll-authority", "ENROLL_AUTHORITY_SIGNER", "")
	if err != nil {
		log.Fatalf("enrollment-authority signer: %v", err)
	}
	enrollPub, err := keystore.Ed25519Public(enrollKey)
	if err != nil {
		log.Fatalf("enrollment-authority signer: %v", err)
	}
	caKey, caSrc, err := resolveSigner("device-ca", "DEVICE_CA_SIGNER", "")
	if err != nil {
		log.Fatalf("device-CA signer: %v", err)
	}
	caPub, err := keystore.Ed25519Public(caKey)
	if err != nil {
		log.Fatalf("device-CA signer: %v", err)
	}
	dirKey, dirSrc, err := resolveSigner("directory", "DIRECTORY_SIGNER", "")
	if err != nil {
		log.Fatalf("directory signer: %v", err)
	}
	dirPub, err := keystore.Ed25519Public(dirKey)
	if err != nil {
		log.Fatalf("directory signer: %v", err)
	}
	log.Printf("signing keys: token=%s crl=%s enroll-authority=%s device-ca=%s directory=%s",
		tokenSrc, crlSrc, enrollSrc, caSrc, dirSrc)

	stake := defaultStakeParams()
	stake.MinSats = int64(atoiOr("STAKE_MIN_SATS", int(stake.MinSats)))
	stake.UnbondingPeriod = time.Duration(atoiOr("STAKE_UNBONDING_HOURS", int(stake.UnbondingPeriod/time.Hour))) * time.Hour
	stake.SlashPercent = atoiOr("STAKE_SLASH_PERCENT", stake.SlashPercent)
	if stake.SlashPercent < 1 || stake.SlashPercent > 100 {
		log.Fatalf("STAKE_SLASH_PERCENT must be 1..100")
	}
	log.Printf("staking: min %d sats to be listed, %s unbonding, %d%% slash on equivocation",
		stake.MinSats, stake.UnbondingPeriod, stake.SlashPercent)

	// E-cash denomination keys are RSA blind-signing keys (RFC 9474), which the
	// Ed25519 keystore does not hold; they live under PAY_KEY_DIR, defaulting to
	// $KEY_DIR/mint when only KEY_DIR is set.
	payKeyDir := os.Getenv("PAY_KEY_DIR")
	if payKeyDir == "" && os.Getenv("KEY_DIR") != "" {
		payKeyDir = filepath.Join(os.Getenv("KEY_DIR"), "mint")
	}
	mint, err := NewMint(payKeyDir, defaultDenominations())
	if err != nil {
		log.Fatalf("e-cash mint: %v", err)
	}
	rails, defaultRail := buildRails()

	srv := &Server{
		store: store, tokens: tokens, crlPub: crlPub, crlSigner: crlKey,
		enrollSigner: enrollKey, enrollPub: enrollPub, deviceCASigner: caKey, deviceCAPub: caPub,
		stake: stake,
		directory: &DirectoryAuthority{
			Name: envOr("DIRECTORY_AUTHORITY_NAME", "cp-1"), Signer: dirKey, Pub: dirPub,
		},
		mint: mint, rails: rails, defaultRail: defaultRail,
		devSettle: os.Getenv("PAY_DEV_SETTLE") == "1",
	}
	if srv.devSettle {
		log.Printf("WARNING: PAY_DEV_SETTLE enabled — /api/pay/dev/settle will mark orders paid without a chain; never set this in production")
	}

	go srv.watchBonds(context.Background(), time.Duration(atoiOr("STAKE_WATCH_SECS", 30))*time.Second)

	// Metrics get their own listener, private by default: on the public API
	// anyone could poll the order and redemption counters and watch for the
	// moment someone pays or redeems.
	metricsAddr := envOr("METRICS_ADDR", "127.0.0.1:9102")
	go func() {
		ms := &http.Server{Addr: metricsAddr, Handler: metricsRoutes(), ReadHeaderTimeout: 5 * time.Second}
		log.Printf("metrics on %s/metrics", metricsAddr)
		if err := ms.ListenAndServe(); err != nil {
			log.Printf("metrics listener stopped: %v", err)
		}
	}()

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
//
// There is no request logger, and nothing reads the client's address or a
// forwarding header: a request leaves no record of who made it. (Recoverer
// prints a panic's value and stack, never the request.)
func routes(srv *Server, label string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(corsMiddleware)
	r.Use(metricsMiddleware)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "store": label})
	})

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/register", srv.handleRegister)
		r.Post("/auth/login", srv.handleLogin)
		r.Get("/crl", srv.handleCRL)                    // tunnel servers fetch this unauthenticated
		r.Get("/public/status", srv.handlePublicStatus) // status pages / uptime monitors

		// Untraceable payments (§20) — deliberately identity-free, so no auth.
		r.Get("/pay/denominations", srv.handleDenominations)
		r.Post("/pay/order", srv.handleCreateOrder)
		r.Get("/pay/order/{id}", srv.handleOrderStatus)
		r.Post("/pay/collect", srv.handleCollect)
		r.Post("/pay/redeem", srv.handleRedeem)
		r.Post("/pay/dev/settle", srv.handleDevSettle) // gated by PAY_DEV_SETTLE

		// One-click enrollment: the token authorizes the claim, so no session.
		r.Post("/enroll/claim", srv.handleEnrollClaim)
		r.Get("/enroll/keys", srv.handleEnrollKeys)

		// Staking: status, slashing evidence, and the directory are public.
		r.Get("/stake/{id}", srv.handleStakeStatus)
		r.Post("/stake/slash", srv.handleStakeSlash)
		r.Post("/stake/dev/settle", srv.handleStakeDevSettle) // gated by PAY_DEV_SETTLE
		r.Get("/directory", srv.handleDirectory)

		r.Group(func(r chi.Router) {
			r.Use(srv.authMiddleware)
			r.Get("/nodes", srv.handleListNodes)
			r.Post("/nodes", srv.handleCreateNode)
			r.Get("/nodes/{id}", srv.handleGetNode)
			r.Delete("/nodes/{id}", srv.handleDeleteNode)
			r.Get("/mixnet", srv.handleMixnetStatus)
			r.Get("/dashboard", srv.handleDashboard)
			r.Get("/stats", srv.handleStats)
			r.Get("/admin/stats", srv.handleAdminStats)
			r.Get("/me", srv.handleMe)
			r.Get("/apikeys", srv.handleListAPIKeys)
			r.Post("/apikeys", srv.handleCreateAPIKey)
			r.Delete("/apikeys/{id}", srv.handleDeleteAPIKey)
			r.Get("/audit", srv.handleListAudit)
			r.Post("/enroll/issue", srv.handleEnrollIssue)
			r.Get("/devices", srv.handleListDevices)
			r.Delete("/devices/{id}", srv.handleRevokeDevice)
			r.Post("/stake/{id}/bond", srv.handleStakeBond)
			r.Post("/stake/{id}/unbond", srv.handleStakeUnbond)
		})
	})
	return r
}

// metricsRoutes is the metrics listener's handler: /metrics and nothing else.
func metricsRoutes() http.Handler {
	r := chi.NewRouter()
	r.Get("/metrics", handleMetrics) // Prometheus scrape target
	return r
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
