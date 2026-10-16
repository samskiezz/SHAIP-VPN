package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockBtcpay stands in for a BTCPay Server: it creates invoices, exposes their
// payment methods, and lets the test flip an invoice to "Settled".
type mockBtcpay struct {
	srv      *httptest.Server
	statuses map[string]string // invoice id -> status
}

func newMockBtcpay() *mockBtcpay {
	m := &mockBtcpay{statuses: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Authorization must be the token.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			w.WriteHeader(401)
			return
		}
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/invoices"):
			id := "inv_test_1"
			m.statuses[id] = "New"
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": id, "status": "New",
				"checkoutLink": m.srv.URL + "/i/" + id,
			})
		case strings.Contains(p, "/payment-methods"):
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"paymentMethod": "BTC",
					"destination":   "bc1qtestaddressxxxxxxxxxxxxxxxxxxxxxxx",
					"paymentLink":   "bitcoin:bc1qtestaddressxxxxxxxxxxxxxxxxxxxxxxx?amount=0.00222222",
				},
				{
					"paymentMethod": "BTC-LightningNetwork",
					"destination":   "lnbc222u1ptest...",
					"paymentLink":   "lightning:lnbc222u1ptest...",
				},
			})
		default:
			// GET invoice: return current status.
			parts := strings.Split(strings.TrimRight(p, "/"), "/")
			id := parts[len(parts)-1]
			st := m.statuses[id]
			if st == "" {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": st})
		}
	})
	m.srv = httptest.NewServer(mux)
	return m
}

func (m *mockBtcpay) close()           { m.srv.Close() }
func (m *mockBtcpay) settle(id string) { m.statuses[id] = "Settled" }

func TestBtcpayRailChargeAndConfirm(t *testing.T) {
	mock := newMockBtcpay()
	defer mock.close()

	rail := NewBtcpayRail(mock.srv.URL, "store_test", "apikey_test")
	if rail.Name() != "btcpay" {
		t.Fatalf("name = %q", rail.Name())
	}

	// Create a charge for a month's price in sats.
	price := Price{BitcoinSats: 222_222}
	q, err := rail.NewCharge(context.Background(), "order-1", price)
	if err != nil {
		t.Fatalf("NewCharge: %v", err)
	}
	if !strings.HasPrefix(q.Address, "bc1q") {
		t.Fatalf("expected a BTC address, got %q", q.Address)
	}
	if q.Meta != "inv_test_1" {
		t.Fatalf("expected invoice id in meta, got %q", q.Meta)
	}
	if !strings.Contains(q.AmountLabel, "BTC") {
		t.Fatalf("amount label = %q", q.AmountLabel)
	}
	if !strings.HasPrefix(q.URI, "bitcoin:") {
		t.Fatalf("expected a bitcoin: URI, got %q", q.URI)
	}

	// Not paid yet.
	paid, err := rail.CheckPaid(context.Background(), q)
	if err != nil {
		t.Fatalf("CheckPaid: %v", err)
	}
	if paid {
		t.Fatal("invoice should not be paid yet")
	}

	// Settle it; now it reports paid.
	mock.settle(q.Meta)
	paid, err = rail.CheckPaid(context.Background(), q)
	if err != nil || !paid {
		t.Fatalf("expected settled invoice to be paid, got paid=%v err=%v", paid, err)
	}
}

func TestFormatBTCAndXMR(t *testing.T) {
	cases := []struct {
		fn   func(uint64) string
		in   uint64
		want string
	}{
		{formatBTC, 100_000_000, "1.0"},
		{formatBTC, 222_222, "0.00222222"},
		{formatBTC, 20_000, "0.0002"},
		{formatXMR, 125_000_000_000, "0.125"},
		{formatXMR, 1_000_000_000_000, "1.0"},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("format(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
