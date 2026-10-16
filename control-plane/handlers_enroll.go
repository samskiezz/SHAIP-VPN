package main

// One-click device enrollment (docs/enrollment.md).
//
//	POST   /api/enroll/issue  (auth)   a one-time token and its pqanon:// deep link
//	POST   /api/enroll/claim  (public) a device certificate, for a valid token plus
//	                                   proof of possession of the device's key
//	GET    /api/enroll/keys   (public) the enrollment-authority and device-CA public
//	                                   keys — what clients and tunnel servers pin
//	GET    /api/devices       (auth)   the caller's enrolled devices
//	DELETE /api/devices/{id}  (auth)   revoke a device (published in the signed CRL)
//
// Tokens and certificates name the account by its opaque user id, never the
// email, so the artifacts carry no personal data.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"pqanon/control-plane/enrollment"
)

const (
	enrollDefaultTTL = 15 * time.Minute
	enrollMaxTTL     = 24 * time.Hour
	deviceCertTTL    = 365 * 24 * time.Hour
	maxDeviceName    = 64
	maxClaimBody     = 16 << 10
)

// ClaimPoPMessage is what the device signs with its identity key to prove it
// holds the key it is enrolling. Prefixed so the signature cannot be replayed
// in any other protocol that key signs. Matched byte-for-byte by the Rust
// client (Identity::sign_enrollment_claim).
func ClaimPoPMessage(token string) []byte {
	return []byte("PQANON-ENROLL-CLAIM-V1:" + token)
}

func (s *Server) enrollmentReady(w http.ResponseWriter) bool {
	if s.enrollSigner == nil || s.deviceCASigner == nil {
		errJSON(w, http.StatusServiceUnavailable, "enrollment not configured")
		return false
	}
	return true
}

// handleEnrollIssue issues a one-time enrollment token for the caller's account.
func (s *Server) handleEnrollIssue(w http.ResponseWriter, r *http.Request) {
	if !s.enrollmentReady(w) {
		return
	}
	var body struct {
		TTLMinutes int `json:"ttl_minutes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // an empty body takes the default
	ttl := enrollDefaultTTL
	if body.TTLMinutes > 0 {
		ttl = time.Duration(body.TTLMinutes) * time.Minute
	}
	if ttl > enrollMaxTTL {
		errJSON(w, http.StatusBadRequest, "ttl_minutes may not exceed 1440")
		return
	}
	// Whole seconds, so the stored expiry and the signed one are identical.
	now := time.Now().UTC().Truncate(time.Second)
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		errJSON(w, http.StatusInternalServerError, "rng failure")
		return
	}
	claims := enrollment.EnrollClaims{
		TokenID: id, Account: userID(r), IssuedAt: now, ExpiresAt: now.Add(ttl), OneTime: true,
	}
	tok, err := enrollment.IssueEnrollToken(s.enrollSigner, claims)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "token signing failed")
		return
	}
	rec := &EnrollToken{TokenID: hex.EncodeToString(id[:]), UserID: userID(r), IssuedAt: now, ExpiresAt: claims.ExpiresAt}
	if err := s.store.CreateEnrollToken(r.Context(), rec); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "enroll.issue", rec.TokenID)
	mEnrollments.WithLabelValues("issued").Inc()
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      tok,
		"url":        enrollment.EnrollURL(tok),
		"token_id":   rec.TokenID,
		"expires_at": claims.ExpiresAt,
	})
}

// handleEnrollClaim turns a valid token into a device certificate. It needs no
// session: the token is the authorization, and the proof of possession shows
// the claimant holds the device key being bound.
func (s *Server) handleEnrollClaim(w http.ResponseWriter, r *http.Request) {
	if !s.enrollmentReady(w) {
		return
	}
	var body struct {
		Token     string `json:"token"`
		DevicePub string `json:"device_pub"` // hex Ed25519 identity key
		PoP       string `json:"pop"`        // hex Ed25519 sig over ClaimPoPMessage(token)
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxClaimBody)).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	reject := func(code int, msg string) {
		mEnrollments.WithLabelValues("rejected").Inc()
		errJSON(w, code, msg)
	}

	now := time.Now().UTC()
	claims, err := enrollment.VerifyEnrollToken(s.enrollPub, body.Token, now)
	switch {
	case errors.Is(err, enrollment.ErrExpired):
		reject(http.StatusUnauthorized, "enrollment token expired")
		return
	case err != nil:
		reject(http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	devPub, err := hex.DecodeString(body.DevicePub)
	if err != nil || len(devPub) != ed25519.PublicKeySize {
		reject(http.StatusBadRequest, "device_pub must be a hex Ed25519 public key")
		return
	}
	pop, err := hex.DecodeString(body.PoP)
	if err != nil || !ed25519.Verify(devPub, ClaimPoPMessage(body.Token), pop) {
		reject(http.StatusBadRequest, "proof of possession failed")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "device"
	}
	if len(name) > maxDeviceName {
		name = name[:maxDeviceName]
	}

	// Sign first (pure computation), then commit atomically: a signing failure
	// burns nothing, and a failed claim just discards the unused certificate.
	var did [16]byte
	if _, err := rand.Read(did[:]); err != nil {
		errJSON(w, http.StatusInternalServerError, "rng failure")
		return
	}
	issued := now.Truncate(time.Second)
	certClaims := enrollment.CertClaims{
		DeviceID: did, Account: claims.Account, DevicePub: devPub,
		IssuedAt: issued, ExpiresAt: issued.Add(deviceCertTTL),
	}
	cert, err := enrollment.IssueDeviceCert(s.deviceCASigner, certClaims)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "certificate signing failed")
		return
	}
	d := &Device{
		ID: hex.EncodeToString(did[:]), UserID: claims.Account, Name: name,
		EdPub: devPub, CertExpires: certClaims.ExpiresAt,
	}
	switch err := s.store.ClaimEnrollment(r.Context(), hex.EncodeToString(claims.TokenID[:]), now, d); {
	case errors.Is(err, ErrTokenClaimed):
		reject(http.StatusConflict, "this enrollment token has already been used")
		return
	case errors.Is(err, ErrDeviceKeyInUse):
		reject(http.StatusConflict, "this device key is already enrolled")
		return
	case errors.Is(err, ErrTokenExpired):
		reject(http.StatusUnauthorized, "enrollment token expired")
		return
	case errors.Is(err, ErrNotFound):
		reject(http.StatusUnauthorized, "invalid enrollment token")
		return
	case err != nil:
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.AppendAudit(r.Context(), &AuditEntry{
		UserID: claims.Account, Action: "device.enroll", Detail: d.ID + " " + d.Name, IP: r.RemoteAddr,
	})
	mEnrollments.WithLabelValues("claimed").Inc()
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_id":     d.ID,
		"cert":          cert,
		"expires_at":    d.CertExpires,
		"device_ca_pub": hex.EncodeToString(s.deviceCAPub),
	})
}

// handleEnrollKeys publishes the public keys clients and tunnel servers pin.
// They belong in client builds and server configs: a client must not fetch and
// trust them at enrollment time, or pinning protects nothing.
func (s *Server) handleEnrollKeys(w http.ResponseWriter, _ *http.Request) {
	if !s.enrollmentReady(w) {
		return
	}
	keys := map[string]string{
		"enroll_authority_pub": hex.EncodeToString(s.enrollPub),
		"device_ca_pub":        hex.EncodeToString(s.deviceCAPub),
		"crl_pub":              hex.EncodeToString(s.crlPub),
	}
	if s.directory != nil {
		keys["directory_authority"] = s.directory.Name
		keys["directory_pub"] = hex.EncodeToString(s.directory.Pub)
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.store.ListDevices(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, devs)
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.RevokeDevice(r.Context(), id, userID(r)); err != nil {
		if errors.Is(err, ErrNotFound) {
			errJSON(w, http.StatusNotFound, "not found")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "device.revoke", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
