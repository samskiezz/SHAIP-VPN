package main

// Prometheus metrics (§16). Everything here is a real counter/histogram the
// /metrics endpoint exposes; the deploy/ alert rules and Grafana dashboard are
// written only against these names, so nothing is scraped that isn't emitted.

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	mRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "requests_total",
		Help: "Total HTTP requests, by method, route pattern, and status.",
	}, []string{"method", "route", "status"})

	mErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "errors_total",
		Help: "HTTP 5xx responses, by route pattern.",
	}, []string{"route"})

	mDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "request_duration_seconds",
		Help: "Request latency in seconds.", Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	mAuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "auth_failures_total",
		Help: "Rejected bearer tokens at the auth middleware.",
	})

	mOrders = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "orders_total",
		Help: "Payment orders created, by rail and denomination.",
	}, []string{"rail", "denom"})

	mRedemptions = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "redemptions_total",
		Help: "Token redemptions, by denomination and result (ok/spent/invalid).",
	}, []string{"denom", "result"})

	mCompClaims = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "comp_claims_total",
		Help: "Comp/discount code claims, by result (ok/invalid/exhausted).",
	}, []string{"result"})

	mEnrollments = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "enrollments_total",
		Help: "Device enrollment events, by result (issued/claimed/rejected).",
	}, []string{"result"})

	mStake = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "stake_events_total",
		Help: "Staking events, by kind (bond_opened/bond_credited/slashed/slash_rejected).",
	}, []string{"kind"})

	startTime = time.Now()
	_         = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "pqanon", Subsystem: "cp", Name: "uptime_seconds",
		Help: "Process uptime in seconds.",
	}, func() float64 { return time.Since(startTime).Seconds() })
)

// statusRecorder captures the response status for the metrics middleware.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// metricsMiddleware records a request count, latency, and 5xx errors. It labels
// by chi's route *pattern* (e.g. /api/pay/order/{id}), not the raw path, so the
// metric cardinality stays bounded.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "other"
		}
		mRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
		mDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		if rec.status >= 500 {
			mErrors.WithLabelValues(route).Inc()
		}
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}
