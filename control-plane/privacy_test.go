package main

// The control plane's privacy guarantees, tested end to end through the real
// router: requests leave no trace in the logs, nothing stored names the person
// or the network they came from, and the endpoints that once kept per-customer
// records are gone.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Addresses a request arrives from, directly and in every forwarding header a
// proxy might add. None may appear in a log line or a stored record.
const (
	peerAddr      = "203.0.113.77"
	forwardedAddr = "198.51.100.88"
	realIPAddr    = "198.51.100.89"
)

// call sends one request as if from peerAddr through a proxy that forwards
// the client's address.
func call(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.RemoteAddr = peerAddr + ":41000"
	req.Header.Set("X-Forwarded-For", forwardedAddr)
	req.Header.Set("X-Real-IP", realIPAddr)
	req.Header.Set("True-Client-IP", forwardedAddr)
	req.Header.Set("Forwarded", "for="+forwardedAddr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// customerJourney runs everything a customer does: register (volunteering an
// email and a name the server must ignore), log in, enroll a device named
// after its owner, create an API key, buy and redeem access, and hit an unknown
// path. It returns the identifiers the journey produced.
func customerJourney(t *testing.T, srv *Server, h http.Handler) map[string]string {
	t.Helper()
	ids := map[string]string{}

	rec := call(t, h, "POST", "/api/auth/register", "", map[string]any{
		"email": "alice@example.com", "name": "Alice Example", "password": "correct horse battery",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	var reg struct {
		AccountNumber string `json:"account_number"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &reg)
	ids["account"] = strings.ReplaceAll(reg.AccountNumber, " ", "")

	// A wrong password, then the right one.
	call(t, h, "POST", "/api/auth/login", "", map[string]any{"account_number": reg.AccountNumber, "password": "wrong password"})
	rec = call(t, h, "POST", "/api/auth/login", "", map[string]any{"account_number": reg.AccountNumber, "password": "correct horse battery"})
	var login struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &login)
	if login.Token == "" {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	tok := login.Token

	call(t, h, "GET", "/api/me", tok, nil)
	call(t, h, "POST", "/api/apikeys", tok, map[string]any{"name": "ci"})

	// Enroll a device that reports its owner's name as the device name.
	rec = call(t, h, "POST", "/api/enroll/issue", tok, map[string]any{})
	var issued struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &issued)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec = call(t, h, "POST", "/api/enroll/claim", "", map[string]any{
		"token": issued.Token, "device_pub": hex.EncodeToString(pub),
		"pop":  hex.EncodeToString(ed25519.Sign(priv, ClaimPoPMessage(issued.Token))),
		"name": "Alice's iPhone",
	})
	var claimed struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &claimed)
	if claimed.DeviceID == "" {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
	}
	ids["device"] = claimed.DeviceID
	call(t, h, "GET", "/api/devices", tok, nil)
	call(t, h, "GET", "/api/audit", tok, nil)

	// Buy and redeem access, polling the order by its id in the URL path.
	blinded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 256))
	rec = call(t, h, "POST", "/api/pay/order", "", map[string]any{"denom": "month", "blinded_tokens": []string{blinded}})
	var order struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &order)
	if order.ID == "" {
		t.Fatalf("order: %d %s", rec.Code, rec.Body.String())
	}
	ids["order"] = order.ID
	call(t, h, "GET", "/api/pay/order/"+order.ID, "", nil)
	call(t, h, "POST", "/api/pay/dev/settle", "", map[string]any{"order_id": order.ID})
	call(t, h, "POST", "/api/pay/collect", "", map[string]any{"order_id": order.ID})
	call(t, h, "POST", "/api/pay/redeem", "", map[string]any{"denom": "month", "token": "AAAA", "signature": "AAAA"})

	call(t, h, "GET", "/api/no-such-thing", tok, nil)
	return ids
}

func newPrivacyServer(t *testing.T) (*Server, http.Handler, *MemStore) {
	t.Helper()
	srv, _, store := newTestServer(t)
	mint, err := NewMint("", []DenomSpec{{ID: "month", DurationDays: 30, PriceAtomic: 125}})
	if err != nil {
		t.Fatal(err)
	}
	srv.mint = mint
	return srv, routes(srv, "memory"), store
}

// No request writes a log line, so none can carry an address, an account
// number, a device id or an order id.
func TestRequestsLeaveNoTraceInTheLogs(t *testing.T) {
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)

	srv, h, _ := newPrivacyServer(t)
	ids := customerJourney(t, srv, h)

	out := logged.String()
	for _, needle := range []string{peerAddr, forwardedAddr, realIPAddr, ids["account"], ids["device"], ids["order"], "/api/"} {
		if strings.Contains(out, needle) {
			t.Fatalf("a log line carries %q:\n%s", needle, out)
		}
	}
	if out != "" {
		t.Fatalf("requests must not be logged at all, got:\n%s", out)
	}
}

// After a full customer journey, nothing in the store holds the address the
// requests came from, or the email and names the customer volunteered.
func TestStoredRecordsHoldNoPersonalData(t *testing.T) {
	srv, h, store := newPrivacyServer(t)
	customerJourney(t, srv, h)

	var dump strings.Builder
	store.mu.RLock()
	for _, u := range store.users {
		fmt.Fprintf(&dump, "%+v\n", *u)
	}
	for _, d := range store.devices {
		fmt.Fprintf(&dump, "%+v\n", *d)
	}
	for _, k := range store.apiKeys {
		fmt.Fprintf(&dump, "%+v\n", *k)
	}
	for _, o := range store.orders {
		fmt.Fprintf(&dump, "%+v\n", *o)
	}
	for _, e := range store.enroll {
		fmt.Fprintf(&dump, "%+v\n", *e)
	}
	fmt.Fprintf(&dump, "%+v\n%+v\n", store.audit, store.spent)
	store.mu.RUnlock()

	all := dump.String()
	for _, needle := range []string{peerAddr, forwardedAddr, realIPAddr, "alice", "Alice", "example.com"} {
		if strings.Contains(all, needle) {
			t.Fatalf("the store holds %q:\n%s", needle, all)
		}
	}
	for _, d := range store.devices {
		if d.Name != "iPhone" {
			t.Fatalf("device name %q: only a platform label may be stored", d.Name)
		}
	}
}

// The endpoints that kept a per-customer connection log, domain lists and
// settings are gone, even for a signed-in caller.
func TestNoPerCustomerRecordEndpoints(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)
	for _, path := range []string{"/api/connections", "/api/connections/x", "/api/routing", "/api/settings"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			if rec := do(t, h, method, path, tok, map[string]any{"domain": "example.com"}); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s answered %d: the endpoint must not exist", method, path, rec.Code)
			}
		}
	}
}

// A session token carries an opaque subject and an expiry, nothing else.
func TestTokenCarriesNothingPersonal(t *testing.T) {
	srv, h, _ := newTestServer(t)
	rec := do(t, h, "POST", "/api/auth/register", "", map[string]any{"password": "password123", "email": "a@b.co"})
	var reg struct {
		AccountNumber string `json:"account_number"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &reg)
	rec = do(t, h, "POST", "/api/auth/login", "", map[string]any{"account_number": reg.AccountNumber, "password": "password123"})
	var login struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &login)
	payload, err := base64.RawURLEncoding.DecodeString(strings.SplitN(login.Token, ".", 2)[0])
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if len(claims) != 2 || claims["sub"] == nil || claims["exp"] == nil {
		t.Fatalf("token claims must be exactly sub and exp, got %v", claims)
	}
	if _, err := srv.tokens.Verify(login.Token); err != nil {
		t.Fatal(err)
	}
}

// Login accepts the account number as displayed, and nothing else.
func TestAccountNumbers(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n, err := newAccountNumber()
		if err != nil || len(n) != accountDigits || strings.Trim(n, "0123456789") != "" {
			t.Fatalf("bad account number %q: %v", n, err)
		}
		if seen[n] {
			t.Fatalf("repeated account number %q", n)
		}
		seen[n] = true
	}
	for in, want := range map[string]string{
		"1234567890123456":    "1234567890123456",
		"1234 5678 9012 3456": "1234567890123456",
		"1234-5678-9012-3456": "1234567890123456",
	} {
		if got, ok := normalizeAccountNumber(in); !ok || got != want {
			t.Fatalf("normalize(%q) = %q %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "123456789012345", "12345678901234567", "1234 5678 9012 345x", "١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦"} {
		if _, ok := normalizeAccountNumber(bad); ok {
			t.Fatalf("normalize(%q) accepted", bad)
		}
	}
	if got := formatAccountNumber("1234567890123456"); got != "1234 5678 9012 3456" {
		t.Fatalf("format: %q", got)
	}
}

// Nobody can read another account's security log, admins included.
func TestAuditLogIsOwnAccountOnly(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, userTok := authedUser(t, srv, store)
	_, adminTok := adminUser(t, srv, store)
	do(t, h, "POST", "/api/apikeys", userTok, map[string]any{"name": "users-key"})

	for _, q := range []string{"", "?all=true"} {
		rec := do(t, h, "GET", "/api/audit"+q, adminTok, nil)
		if strings.Contains(rec.Body.String(), "users-key") {
			t.Fatalf("an admin read another account's audit log (%q): %s", q, rec.Body.String())
		}
	}
	rec := do(t, h, "GET", "/api/audit", userTok, nil)
	if !strings.Contains(rec.Body.String(), "users-key") {
		t.Fatalf("the owner must see their own entry: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"ip"`) || strings.Contains(rec.Body.String(), "192.0.2.1") {
		t.Fatalf("an audit entry carries an address: %s", rec.Body.String())
	}
}

func TestDeviceLabels(t *testing.T) {
	for in, want := range map[string]string{
		"iPhone": "iPhone", "iphone": "iPhone", " Mac ": "Mac", "linux": "Linux",
		"Alice's iPhone": "iPhone", "johns-macbook": "Mac", "Pixel 8 (Android)": "Android",
		"": "device", "DESKTOP-4F2A9": "device", "Alice Example": "device",
	} {
		if got := deviceLabel(in); got != want {
			t.Fatalf("deviceLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTimesAreDays(t *testing.T) {
	at := time.Date(2026, 10, 16, 13, 45, 7, 123, time.FixedZone("AEST", 10*3600))
	if got := day(at); !got.Equal(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("day = %v", got)
	}
	if got := dayCeil(at); !got.Equal(time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("dayCeil = %v", got)
	}
	midnight := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	if got := dayCeil(midnight); !got.Equal(midnight) {
		t.Fatalf("dayCeil must be idempotent: %v", got)
	}
}

func TestRedactAddrs(t *testing.T) {
	for in, want := range map[string]string{
		"dial tcp 10.0.0.5:5432: connect: connection refused": "dial tcp [addr]: connect: connection refused",
		"peer=203.0.113.7 sent junk":                          "peer=[addr] sent junk",
		"from [2001:db8::1]:443 and fe80::1%eth0.":            "from [[addr]]:443 and [addr]%eth0.",
		"id7a192.0.2.1:80,":                                   "id7a[addr],",
		"oid 1.2.3.4.5 and ab:cd:ef":                          "oid 1.2.3.4.5 and ab:cd:ef",
		"http://192.0.2.10:18082/json_rpc":                    "http://[addr]/json_rpc",
		"::ffff:198.51.100.4 mapped":                          "[addr] mapped",
		"2026/10/16 12:34:56 listening on :8080":              "2026/10/16 12:34:56 listening on :8080",
		"go1.22.3 build abcdef0123456789":                     "go1.22.3 build abcdef0123456789",
		"rate 0.5 of 1.25":                                    "rate 0.5 of 1.25",
	} {
		if got := string(redactAddrs([]byte(in))); got != want {
			t.Errorf("redactAddrs(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	var buf bytes.Buffer
	l := log.New(&redactingWriter{w: &buf}, "", 0)
	l.Printf("http: panic serving %s:%d: boom", peerAddr, 41000)
	if strings.Contains(buf.String(), peerAddr) || !strings.Contains(buf.String(), redactedAddr) {
		t.Fatalf("redacting writer let an address through: %q", buf.String())
	}
}
