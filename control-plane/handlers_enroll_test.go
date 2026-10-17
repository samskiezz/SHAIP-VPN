package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"shaip/control-plane/enrollment"
)

// newDeviceKey is a device's Ed25519 identity key.
func newDeviceKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// claimBody builds a claim with a valid proof of possession for key.
func claimBody(token string, pub ed25519.PublicKey, priv ed25519.PrivateKey, name string) map[string]any {
	return map[string]any{
		"token":      token,
		"device_pub": hex.EncodeToString(pub),
		"pop":        hex.EncodeToString(ed25519.Sign(priv, ClaimPoPMessage(token))),
		"name":       name,
	}
}

func issueToken(t *testing.T, h http.Handler, tok string) string {
	t.Helper()
	rec := do(t, h, "POST", "/api/enroll/issue", tok, map[string]any{})
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !strings.HasPrefix(out.URL, "shaip://enroll?t=") || !strings.Contains(out.URL, out.Token) {
		t.Fatalf("bad deep link %q", out.URL)
	}
	return out.Token
}

func TestEnrollIssueRequiresAuth(t *testing.T) {
	_, h, _ := newTestServer(t)
	if rec := do(t, h, "POST", "/api/enroll/issue", "", map[string]any{}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestEnrollClaimIssuesBoundCertificateOnce(t *testing.T) {
	srv, h, store := newTestServer(t)
	uid, tok := authedUser(t, srv, store)
	token := issueToken(t, h, tok)

	// The token names the account by its opaque id (only the device sees it).
	claims, err := enrollment.VerifyEnrollToken(srv.enrollPub, token, time.Now())
	if err != nil || claims.Account != uid || !claims.OneTime {
		t.Fatalf("token claims: %v %+v", err, claims)
	}

	pub, priv := newDeviceKey(t)
	rec := do(t, h, "POST", "/api/enroll/claim", "", claimBody(token, pub, priv, "laptop"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("claim: %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		DeviceID string `json:"device_id"`
		Cert     string `json:"cert"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	// The certificate verifies under the device CA and binds exactly this key.
	// It names no account (tunnel servers see it) and was issued on a UTC day
	// boundary, not at the moment of the claim.
	cert, err := enrollment.VerifyDeviceCert(srv.deviceCAPub, out.Cert, time.Now())
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	if !ed25519.PublicKey(cert.DevicePub).Equal(pub) || hex.EncodeToString(cert.DeviceID[:]) != out.DeviceID {
		t.Fatalf("cert binds the wrong thing: %+v", cert)
	}
	if cert.Account != enrollment.WithheldAccount || strings.Contains(out.Cert, uid) {
		t.Fatalf("the certificate must not name the account: %+v", cert)
	}
	if !cert.IssuedAt.Equal(day(cert.IssuedAt)) {
		t.Fatalf("certificate issued at a moment, not a day: %v", cert.IssuedAt)
	}

	// One-time: the same token cannot enroll a second device.
	pub2, priv2 := newDeviceKey(t)
	if rec := do(t, h, "POST", "/api/enroll/claim", "", claimBody(token, pub2, priv2, "phone")); rec.Code != http.StatusConflict {
		t.Fatalf("second claim: expected 409, got %d", rec.Code)
	}

	// The device is listed for its owner.
	rec = do(t, h, "GET", "/api/devices", tok, nil)
	var devs []Device
	_ = json.Unmarshal(rec.Body.Bytes(), &devs)
	// "laptop" is not a platform label, so it is stored as "device".
	if len(devs) != 1 || devs[0].ID != out.DeviceID || devs[0].Name != "device" || devs[0].EdPubHex != hex.EncodeToString(pub) {
		t.Fatalf("devices: %+v", devs)
	}
}

func TestEnrollClaimRejections(t *testing.T) {
	srv, h, store := newTestServer(t)
	uid, tok := authedUser(t, srv, store)
	pub, priv := newDeviceKey(t)

	claim := func(body map[string]any) int {
		return do(t, h, "POST", "/api/enroll/claim", "", body).Code
	}

	// Garbage and foreign tokens.
	if c := claim(claimBody("PQE1.junk.junk", pub, priv, "x")); c != http.StatusUnauthorized {
		t.Fatalf("garbage token: %d", c)
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	foreign, _ := enrollment.IssueEnrollToken(otherKey, enrollment.EnrollClaims{
		Account: uid, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), OneTime: true,
	})
	if c := claim(claimBody(foreign, pub, priv, "x")); c != http.StatusUnauthorized {
		t.Fatalf("token from another authority: %d", c)
	}

	// A correctly signed token the store never issued is refused.
	unissued, _ := enrollment.IssueEnrollToken(srv.enrollSigner, enrollment.EnrollClaims{
		TokenID: [16]byte{9}, Account: uid, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour), OneTime: true,
	})
	if c := claim(claimBody(unissued, pub, priv, "x")); c != http.StatusUnauthorized {
		t.Fatalf("unissued token: %d", c)
	}

	// An expired token is refused.
	past := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	expID := [16]byte{7}
	exp, _ := enrollment.IssueEnrollToken(srv.enrollSigner, enrollment.EnrollClaims{
		TokenID: expID, Account: uid, IssuedAt: past, ExpiresAt: past.Add(time.Minute), OneTime: true,
	})
	_ = store.CreateEnrollToken(context.Background(), &EnrollToken{
		TokenID: hex.EncodeToString(expID[:]), UserID: uid, IssuedAt: past, ExpiresAt: past.Add(time.Minute),
	})
	rec := do(t, h, "POST", "/api/enroll/claim", "", claimBody(exp, pub, priv, "x"))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("expired token: %d %s", rec.Code, rec.Body.String())
	}

	// A proof of possession by the wrong key is refused — and does not burn the
	// token: the real key can still claim it afterwards.
	token := issueToken(t, h, tok)
	_, wrongPriv := newDeviceKey(t)
	if c := claim(claimBody(token, pub, wrongPriv, "x")); c != http.StatusBadRequest {
		t.Fatalf("bad proof of possession: %d", c)
	}
	bad := claimBody(token, pub, priv, "x")
	bad["device_pub"] = "abcd"
	if c := claim(bad); c != http.StatusBadRequest {
		t.Fatalf("short device key: %d", c)
	}
	if c := claim(claimBody(token, pub, priv, "laptop")); c != http.StatusCreated {
		t.Fatalf("valid claim after rejected attempts: %d", c)
	}

	// The same device key cannot be enrolled twice, even with a fresh token, and
	// that failure leaves the fresh token claimable.
	token2 := issueToken(t, h, tok)
	if c := claim(claimBody(token2, pub, priv, "again")); c != http.StatusConflict {
		t.Fatalf("re-enrolling a key: %d", c)
	}
	pub3, priv3 := newDeviceKey(t)
	if c := claim(claimBody(token2, pub3, priv3, "tablet")); c != http.StatusCreated {
		t.Fatalf("token2 must survive the failed claim: %d", c)
	}
}

func TestRevokedDeviceAppearsInSignedCRL(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)
	token := issueToken(t, h, tok)
	pub, priv := newDeviceKey(t)
	rec := do(t, h, "POST", "/api/enroll/claim", "", claimBody(token, pub, priv, "laptop"))
	var out struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	if rec := do(t, h, "DELETE", "/api/devices/"+out.DeviceID, tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}

	rec = do(t, h, "GET", "/api/crl", "", nil)
	var crl struct {
		CRL    json.RawMessage `json:"crl"`
		CRLB64 string          `json:"crl_b64"`
		Sig    string          `json:"ed25519_sig"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &crl)
	signed, err := base64.StdEncoding.DecodeString(crl.CRLB64)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(crl.Sig)
	if !ed25519.Verify(srv.crlPub, signed, sig) {
		t.Fatal("CRL signature does not verify over crl_b64")
	}
	if string(signed) != string(crl.CRL) {
		t.Fatal("crl_b64 must be exactly the bytes served as crl")
	}
	var body struct {
		RevokedDevices []struct {
			DeviceID string `json:"device_id"`
		} `json:"revoked_devices"`
	}
	_ = json.Unmarshal(signed, &body)
	if len(body.RevokedDevices) != 1 || body.RevokedDevices[0].DeviceID != out.DeviceID {
		t.Fatalf("revoked device missing from the signed CRL: %s", signed)
	}
}

func TestDevicesAreIsolatedPerAccount(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tokA := authedUser(t, srv, store)
	ub := newUser(t, store, "")
	tokB, _ := srv.tokens.Issue(ub.ID)

	token := issueToken(t, h, tokA)
	pub, priv := newDeviceKey(t)
	rec := do(t, h, "POST", "/api/enroll/claim", "", claimBody(token, pub, priv, "a-laptop"))
	var out struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	rec = do(t, h, "GET", "/api/devices", tokB, nil)
	var devs []Device
	_ = json.Unmarshal(rec.Body.Bytes(), &devs)
	if len(devs) != 0 {
		t.Fatalf("B sees A's devices: %+v", devs)
	}
	if rec := do(t, h, "DELETE", "/api/devices/"+out.DeviceID, tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("B revoking A's device: %d", rec.Code)
	}
}

func TestEnrollKeysArePublic(t *testing.T) {
	srv, h, _ := newTestServer(t)
	rec := do(t, h, "GET", "/api/enroll/keys", "", nil)
	var keys map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &keys)
	if keys["enroll_authority_pub"] != hex.EncodeToString(srv.enrollPub) ||
		keys["device_ca_pub"] != hex.EncodeToString(srv.deviceCAPub) ||
		keys["crl_pub"] != hex.EncodeToString(srv.crlPub) {
		t.Fatalf("keys: %v", keys)
	}
}
