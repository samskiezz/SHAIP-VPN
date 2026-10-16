package main

// The HTTP surface, shared by the server (main.go) and the WebAssembly build
// for the hosted web preview (wasm_main.go).

import (
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// routes builds the HTTP handler. Extracted from main so tests can exercise
// the real router, middleware stack, and auth group.
//
// There is no request logger, and nothing reads the client's address or a
// forwarding header: a request leaves no record of who made it.
func routes(srv *Server, label string) http.Handler {
	r := chi.NewRouter()
	r.Use(recoverer)
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
			r.Delete("/me", srv.handleDeleteAccount)
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

// recoverer turns a handler panic into a 500. It logs the panic and its stack
// through the standard logger (so through the address redactor), and nothing
// about the request.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v) // net/http's own signal; it logs nothing for it
				}
				log.Printf("panic in a request handler: %v\n%s", v, debug.Stack())
				errJSON(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// metricsRoutes is the metrics listener's handler: /metrics and nothing else.
func metricsRoutes() http.Handler {
	r := chi.NewRouter()
	r.Get("/metrics", handleMetrics) // Prometheus scrape target
	return r
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
