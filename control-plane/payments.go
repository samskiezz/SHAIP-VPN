package main

// Payment rails (§20). A rail turns an order into a payment request and later
// reports whether it was paid. The e-cash layer above is rail-agnostic, so BTC,
// Lightning and Monero all feed the *same* unlinkable blind-token flow: whatever
// coin funds the order, the tokens the mint signs can't be linked back to it.
//
//   - Monero  — the privacy coin; per-order subaddress, amounts hidden on-chain.
//   - BTCPay  — self-hosted Bitcoin + Lightning, no KYC, no processor.
//   - dev     — no chain, for local/CI; settlement is manual and gated.
//
// A denomination carries a price in each coin's own unit (piconero and sats), so
// no live exchange-rate feed is needed — the operator sets both.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Price is a denomination's cost in each supported coin's native unit.
type Price struct {
	MoneroAtomic uint64 // piconero (1 XMR = 1e12)
	BitcoinSats  uint64 // satoshis (1 BTC = 1e8)
}

// RailQuote is everything a buyer needs to pay, plus opaque routing the rail
// uses later to recognise the payment.
type RailQuote struct {
	Address     string `json:"address"`
	Meta        string `json:"-"`            // rail-private routing
	AmountLabel string `json:"amount_label"` // e.g. "0.125 XMR" / "0.00032 BTC"
	URI         string `json:"uri,omitempty"`
}

// PaymentRail is a pluggable payment backend.
type PaymentRail interface {
	Name() string
	// NewCharge creates a payment request for `price` and labels it with orderID.
	NewCharge(ctx context.Context, orderID string, price Price) (RailQuote, error)
	// CheckPaid reports whether the charge described by q has been paid and
	// sufficiently confirmed. Everything it needs is in q (set at NewCharge).
	CheckPaid(ctx context.Context, q RailQuote) (bool, error)
}

// ---------------------------------------------------------------------------
// Dev rail: no chain. Manual settlement via Settle (gated in the API).
// ---------------------------------------------------------------------------

type DevRail struct {
	mu   sync.Mutex
	paid map[string]uint64
	seq  int
}

func NewDevRail() *DevRail { return &DevRail{paid: make(map[string]uint64)} }

func (r *DevRail) Name() string { return "dev" }

func (r *DevRail) NewCharge(_ context.Context, orderID string, price Price) (RailQuote, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	return RailQuote{
		Address:     fmt.Sprintf("dev:%s:%d", orderID, r.seq),
		Meta:        strconv.FormatUint(price.MoneroAtomic, 10), // expected
		AmountLabel: formatXMR(price.MoneroAtomic) + " XMR",
	}, nil
}

func (r *DevRail) CheckPaid(_ context.Context, q RailQuote) (bool, error) {
	expected, _ := strconv.ParseUint(q.Meta, 10, 64)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.paid[q.Address] >= expected, nil
}

// Settle marks an address paid (dev/test only).
func (r *DevRail) Settle(address string, amount uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paid[address] = amount
}

// ---------------------------------------------------------------------------
// Monero rail: JSON-RPC to monero-wallet-rpc.
// ---------------------------------------------------------------------------

type MoneroRail struct {
	url     string
	http    *http.Client
	account uint32
	minConf int
	user    string
	pass    string
}

func NewMoneroRail(url string, account uint32, minConf int, user, pass string) *MoneroRail {
	if minConf <= 0 {
		minConf = 10
	}
	return &MoneroRail{
		url: url, http: &http.Client{Timeout: 15 * time.Second},
		account: account, minConf: minConf, user: user, pass: pass,
	}
}

func (r *MoneroRail) Name() string { return "monero" }

func (r *MoneroRail) call(ctx context.Context, method string, params, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "0", "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url+"/json_rpc", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.user != "" {
		req.SetBasicAuth(r.user, r.pass)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if env.Error != nil {
		return fmt.Errorf("monero %s: %s (%d)", method, env.Error.Message, env.Error.Code)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (r *MoneroRail) NewCharge(ctx context.Context, orderID string, price Price) (RailQuote, error) {
	var res struct {
		Address      string `json:"address"`
		AddressIndex uint32 `json:"address_index"`
	}
	if err := r.call(ctx, "create_address", map[string]any{
		"account_index": r.account, "label": "order:" + orderID,
	}, &res); err != nil {
		return RailQuote{}, err
	}
	xmr := formatXMR(price.MoneroAtomic)
	return RailQuote{
		Address:     res.Address,
		Meta:        fmt.Sprintf("%d|%d", res.AddressIndex, price.MoneroAtomic),
		AmountLabel: xmr + " XMR",
		URI:         fmt.Sprintf("monero:%s?tx_amount=%s", res.Address, xmr),
	}, nil
}

func (r *MoneroRail) CheckPaid(ctx context.Context, q RailQuote) (bool, error) {
	parts := strings.SplitN(q.Meta, "|", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("bad monero meta %q", q.Meta)
	}
	idx, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return false, err
	}
	expected, _ := strconv.ParseUint(parts[1], 10, 64)
	var res struct {
		In []struct {
			Amount        uint64 `json:"amount"`
			Confirmations uint64 `json:"confirmations"`
		} `json:"in"`
	}
	if err := r.call(ctx, "get_transfers", map[string]any{
		"in": true, "pending": true, "account_index": r.account,
		"subaddr_indices": []uint32{uint32(idx)},
	}, &res); err != nil {
		return false, err
	}
	var total uint64
	for _, t := range res.In {
		if int(t.Confirmations) >= r.minConf {
			total += t.Amount
		}
	}
	return total >= expected, nil
}

// ---------------------------------------------------------------------------
// BTCPay rail: Bitcoin + Lightning via a self-hosted BTCPay Server (no KYC).
// ---------------------------------------------------------------------------

type BtcpayRail struct {
	baseURL string
	storeID string
	apiKey  string
	http    *http.Client
}

func NewBtcpayRail(baseURL, storeID, apiKey string) *BtcpayRail {
	return &BtcpayRail{
		baseURL: strings.TrimRight(baseURL, "/"),
		storeID: storeID, apiKey: apiKey,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

func (r *BtcpayRail) Name() string { return "btcpay" }

func (r *BtcpayRail) do(ctx context.Context, method, path string, body, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return fmt.Errorf("btcpay %s %s: %d %s", method, path, resp.StatusCode, buf.String())
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (r *BtcpayRail) NewCharge(ctx context.Context, orderID string, price Price) (RailQuote, error) {
	btc := formatBTC(price.BitcoinSats)
	reqBody := map[string]any{
		"amount":   btc,
		"currency": "BTC",
		"metadata": map[string]string{"orderId": orderID, "source": "pqanon"},
		"checkout": map[string]any{"expirationMinutes": 30},
	}
	var inv struct {
		ID           string `json:"id"`
		CheckoutLink string `json:"checkoutLink"`
	}
	if err := r.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/v1/stores/%s/invoices", r.storeID), reqBody, &inv); err != nil {
		return RailQuote{}, err
	}

	// Payment methods give the on-chain address and the LN invoice.
	var methods []struct {
		PaymentMethod string `json:"paymentMethod"`
		Destination   string `json:"destination"`
		PaymentLink   string `json:"paymentLink"`
	}
	addr, uri := inv.CheckoutLink, inv.CheckoutLink
	if err := r.do(ctx, http.MethodGet,
		fmt.Sprintf("/api/v1/stores/%s/invoices/%s/payment-methods", r.storeID, inv.ID),
		nil, &methods); err == nil {
		for _, m := range methods {
			if strings.HasPrefix(m.PaymentMethod, "BTC") {
				addr = m.Destination
				if m.PaymentLink != "" {
					uri = m.PaymentLink
				}
				break
			}
		}
	}
	return RailQuote{
		Address:     addr,
		Meta:        inv.ID,
		AmountLabel: btc + " BTC",
		URI:         uri,
	}, nil
}

func (r *BtcpayRail) CheckPaid(ctx context.Context, q RailQuote) (bool, error) {
	var inv struct {
		Status string `json:"status"`
	}
	if err := r.do(ctx, http.MethodGet,
		fmt.Sprintf("/api/v1/stores/%s/invoices/%s", r.storeID, q.Meta), nil, &inv); err != nil {
		return false, err
	}
	// BTCPay: New, Processing, Settled, Expired, Invalid. "Settled" means paid
	// and sufficiently confirmed per the store's speed policy.
	switch inv.Status {
	case "Settled", "Complete", "Confirmed":
		return true, nil
	default:
		return false, nil
	}
}

// ---------------------------------------------------------------------------

// formatXMR renders piconero as a trimmed XMR decimal string (no unit).
func formatXMR(atomic uint64) string { return trimDecimal(atomic, 12) }

// formatBTC renders satoshis as a trimmed BTC decimal string (no unit).
func formatBTC(sats uint64) string { return trimDecimal(sats, 8) }

func trimDecimal(amount uint64, decimals int) string {
	unit := uint64(1)
	for i := 0; i < decimals; i++ {
		unit *= 10
	}
	whole := amount / unit
	frac := amount % unit
	s := fmt.Sprintf("%d.%0*d", whole, decimals, frac)
	i := len(s) - 1
	for i > 0 && s[i] == '0' && s[i-1] != '.' {
		i--
	}
	return s[:i+1]
}
