package main

// Payment rails (§20). A rail turns an order into a one-time payment address and
// later reports whether that address has been paid, with enough confirmations.
// The mint doesn't care which coin it is, so new rails (BTC/Lightning) can be
// added behind this interface without touching the e-cash logic.
//
// Monero is the default because it is the privacy coin: amounts, sender and
// receiver are hidden on-chain, so even the payment leg leaks nothing. A buyer
// pays a unique subaddress per order; any confirmed payment of at least the
// quoted amount settles it. No name, email or card ever touches the system.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RailQuote is a payment address plus rail-specific routing data (for Monero,
// the subaddress index to filter transfers by).
type RailQuote struct {
	Address string `json:"address"`
	Meta    string `json:"meta,omitempty"`
}

// PaymentRail is a pluggable payment backend.
type PaymentRail interface {
	// Name is a short identifier shown to the buyer (e.g. "monero", "dev").
	Name() string
	// NewAddress returns a fresh, order-specific address to pay.
	NewAddress(ctx context.Context, orderID string) (RailQuote, error)
	// CheckPaid reports whether the address has received at least
	// expectedAtomic in confirmed funds, and how much it has received.
	CheckPaid(ctx context.Context, q RailQuote, expectedAtomic uint64) (confirmed bool, received uint64, err error)
}

// ---------------------------------------------------------------------------
// Dev rail: no chain. Lets a local/CI deployment exercise the full buy→collect→
// redeem flow without a live Monero node. Settlement is explicit (Settle), gated
// in the API by PAY_DEV_SETTLE so it can never be reached in production.
// ---------------------------------------------------------------------------

type DevRail struct {
	mu   sync.Mutex
	paid map[string]uint64 // address -> confirmed atomic
	seq  int
}

func NewDevRail() *DevRail { return &DevRail{paid: make(map[string]uint64)} }

func (r *DevRail) Name() string { return "dev" }

func (r *DevRail) NewAddress(_ context.Context, orderID string) (RailQuote, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	return RailQuote{Address: fmt.Sprintf("dev:%s:%d", orderID, r.seq)}, nil
}

func (r *DevRail) CheckPaid(_ context.Context, q RailQuote, expected uint64) (bool, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	got := r.paid[q.Address]
	return got >= expected, got, nil
}

// Settle marks an address as paid (dev/test only).
func (r *DevRail) Settle(address string, amount uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paid[address] = amount
}

// ---------------------------------------------------------------------------
// Monero rail: talks JSON-RPC to monero-wallet-rpc (which fronts a monerod).
// ---------------------------------------------------------------------------

type MoneroRail struct {
	url       string
	http      *http.Client
	account   uint32
	minConf   int
}

// NewMoneroRail builds a rail against a monero-wallet-rpc endpoint, e.g.
// http://127.0.0.1:18083/json_rpc. minConf is the confirmation threshold before
// an order is considered paid (10 is a common safe default).
func NewMoneroRail(url string, account uint32, minConf int) *MoneroRail {
	if minConf <= 0 {
		minConf = 10
	}
	return &MoneroRail{
		url:     url,
		http:    &http.Client{Timeout: 15 * time.Second},
		account: account,
		minConf: minConf,
	}
}

func (r *MoneroRail) Name() string { return "monero" }

type moneroReq struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type moneroResp struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (r *MoneroRail) call(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(moneroReq{JSONRPC: "2.0", ID: "0", Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var mr moneroResp
	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		return err
	}
	if mr.Error != nil {
		return fmt.Errorf("monero-wallet-rpc %s: %s (code %d)", method, mr.Error.Message, mr.Error.Code)
	}
	if out != nil {
		return json.Unmarshal(mr.Result, out)
	}
	return nil
}

func (r *MoneroRail) NewAddress(ctx context.Context, orderID string) (RailQuote, error) {
	var res struct {
		Address      string `json:"address"`
		AddressIndex uint32 `json:"address_index"`
	}
	err := r.call(ctx, "create_address", map[string]any{
		"account_index": r.account,
		"label":         "order:" + orderID,
	}, &res)
	if err != nil {
		return RailQuote{}, err
	}
	return RailQuote{Address: res.Address, Meta: strconv.FormatUint(uint64(res.AddressIndex), 10)}, nil
}

func (r *MoneroRail) CheckPaid(ctx context.Context, q RailQuote, expected uint64) (bool, uint64, error) {
	idx, err := strconv.ParseUint(q.Meta, 10, 32)
	if err != nil {
		return false, 0, fmt.Errorf("bad subaddress index %q: %w", q.Meta, err)
	}
	var res struct {
		In []struct {
			Amount        uint64 `json:"amount"`
			Confirmations uint64 `json:"confirmations"`
		} `json:"in"`
	}
	err = r.call(ctx, "get_transfers", map[string]any{
		"in":              true,
		"pending":         true,
		"account_index":   r.account,
		"subaddr_indices": []uint32{uint32(idx)},
	}, &res)
	if err != nil {
		return false, 0, err
	}
	var total uint64
	for _, t := range res.In {
		if int(t.Confirmations) >= r.minConf {
			total += t.Amount
		}
	}
	return total >= expected, total, nil
}

// formatXMR renders atomic units as a human XMR string (12 decimals).
func formatXMR(atomic uint64) string {
	const unit = 1_000_000_000_000
	whole := atomic / unit
	frac := atomic % unit
	s := fmt.Sprintf("%d.%012d", whole, frac)
	// trim trailing zeros but keep at least 2 decimals
	i := len(s) - 1
	for i > 0 && s[i] == '0' && s[i-1] != '.' {
		i--
	}
	return s[:i+1]
}
