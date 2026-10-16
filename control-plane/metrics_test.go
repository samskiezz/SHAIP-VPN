package main

import (
	"net/http"
	"strings"
	"testing"
)

// TestMetricsEndpointExposesRealSeries drives a couple of requests through the
// router and asserts /metrics reports the series the deploy/ rules rely on.
func TestMetricsEndpointExposesRealSeries(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)

	// A 200 (authed) and a 401 (no token) so both request and auth-failure
	// counters advance.
	do(t, h, "GET", "/api/me", tok, nil)
	do(t, h, "GET", "/api/me", "", nil)

	// /metrics is served on its own private listener, never the public API.
	if rec := do(t, h, "GET", "/metrics", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("the public API must not serve /metrics, got %d", rec.Code)
	}
	rec := do(t, metricsRoutes(), "GET", "/metrics", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics: %d", rec.Code)
	}
	body := rec.Body.String()
	// These always have samples (every request advances them). The payment
	// counters (orders/redemptions) only emit once labelled, so they are
	// asserted in the payment-flow test, which actually redeems.
	for _, want := range []string{
		"pqanon_cp_requests_total",
		"pqanon_cp_request_duration_seconds",
		"pqanon_cp_auth_failures_total",
		"pqanon_cp_uptime_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing series %q", want)
		}
	}
	// The route is labelled by chi pattern, not the raw path.
	if !strings.Contains(body, `route="/api/me"`) {
		t.Errorf("expected route pattern label /api/me in metrics:\n%s", body)
	}
}
