package main

// Node staking (docs/staking.md).
//
//	POST /api/stake/{node}/bond    (operator) open a charge that bonds stake once paid
//	POST /api/stake/{node}/unbond  (operator) start unbonding (stays slashable until released)
//	GET  /api/stake/{node}         (public)   stake status; credits newly paid bonds
//	POST /api/stake/slash          (public)   two conflicting signed descriptors → slash + jail
//	POST /api/stake/dev/settle     (dev only) settle a bond on the dev rail (PAY_DEV_SETTLE)
//	GET  /api/directory            (public)   signed consensus of bonded, unjailed nodes
//
// Stake is denominated in satoshis, so bonds use a sats-denominated rail
// (BTCPay, or dev in tests). Slashing is permissionless: the evidence proves
// itself against the key the node registered, so the reporter is not trusted.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"shaip/control-plane/directory"
	"shaip/control-plane/staking"
)

const maxBondSats = 21_000_000 * 100_000_000 // all the bitcoin there is

// StakeParams are the staking rules.
type StakeParams struct {
	MinSats         int64         // bonded stake a node needs to be listed
	UnbondingPeriod time.Duration // how long unbonding stake stays slashable
	SlashPercent    int           // share of at-risk stake an equivocation burns
}

func defaultStakeParams() StakeParams {
	return StakeParams{MinSats: 100_000, UnbondingPeriod: 14 * 24 * time.Hour, SlashPercent: 50}
}

// DirectoryAuthority is this control plane acting as a directory authority.
type DirectoryAuthority struct {
	Name   string
	Signer crypto.Signer
	Pub    ed25519.PublicKey
}

// operatorNode loads a node and checks the caller operates it (or is an admin).
func (s *Server) operatorNode(w http.ResponseWriter, r *http.Request) (*Node, bool) {
	n, err := s.store.GetNode(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, "node not found")
		return nil, false
	}
	if n.OwnerID != userID(r) {
		if u, err := s.store.GetUserByID(r.Context(), userID(r)); err != nil || u.Role != "admin" {
			errJSON(w, http.StatusForbidden, "only the node's operator can do that")
			return nil, false
		}
	}
	return n, true
}

func (s *Server) handleStakeBond(w http.ResponseWriter, r *http.Request) {
	n, ok := s.operatorNode(w, r)
	if !ok {
		return
	}
	if n.JailedAt != nil {
		errJSON(w, http.StatusConflict, "node is jailed")
		return
	}
	if len(n.EdPub) != ed25519.PublicKeySize {
		errJSON(w, http.StatusConflict, "register the node's ed_pub first: slashing evidence is verified against it")
		return
	}
	var body struct {
		AmountSats int64  `json:"amount_sats"`
		Rail       string `json:"rail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.AmountSats <= 0 || body.AmountSats > maxBondSats {
		errJSON(w, http.StatusBadRequest, "amount_sats must be positive")
		return
	}
	rail, ok := s.railFor(body.Rail)
	if !ok {
		errJSON(w, http.StatusBadRequest, "unknown payment rail")
		return
	}
	if rail.Name() != "btcpay" && rail.Name() != "dev" {
		errJSON(w, http.StatusBadRequest, "stake is denominated in satoshis: bond with the btcpay rail")
		return
	}
	b := &StakeBond{ID: uuid.NewString(), NodeID: n.ID, AmountSats: body.AmountSats, Rail: rail.Name()}
	quote, err := rail.NewCharge(r.Context(), "bond-"+b.ID, Price{
		BitcoinSats: uint64(body.AmountSats), MoneroAtomic: uint64(body.AmountSats), // dev rail settles in raw units
	})
	if err != nil {
		errJSON(w, http.StatusBadGateway, "payment rail: "+err.Error())
		return
	}
	b.Quote = quote
	if err := s.store.CreateBond(r.Context(), b); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "stake.bond", n.ID+" "+b.ID)
	mStake.WithLabelValues("bond_opened").Inc()
	writeJSON(w, http.StatusCreated, map[string]any{
		"bond_id":      b.ID,
		"status":       b.Status,
		"address":      quote.Address,
		"amount_label": quote.AmountLabel,
		"uri":          quote.URI,
	})
}

func (s *Server) handleStakeUnbond(w http.ResponseWriter, r *http.Request) {
	n, ok := s.operatorNode(w, r)
	if !ok {
		return
	}
	var body struct {
		AmountSats int64 `json:"amount_sats"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AmountSats <= 0 {
		errJSON(w, http.StatusBadRequest, "amount_sats must be positive")
		return
	}
	release := time.Now().UTC().Add(s.stake.UnbondingPeriod)
	switch err := s.store.Unbond(r.Context(), n.ID, body.AmountSats, release); {
	case errors.Is(err, ErrInsufficientStake):
		errJSON(w, http.StatusConflict, "not that much bonded stake")
		return
	case err != nil:
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "stake.unbond", n.ID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "unbonding", "release_at": release})
}

// creditPaidBonds credits every awaiting bond whose charge has been paid, and
// returns how many it credited. Crediting is exactly-once in the store.
func (s *Server) creditPaidBonds(ctx context.Context, bonds []StakeBond) int {
	credited := 0
	for _, b := range bonds {
		if b.Status != "awaiting_payment" {
			continue
		}
		rail, ok := s.rails[b.Rail]
		if !ok {
			continue
		}
		if paid, err := rail.CheckPaid(ctx, b.Quote); err != nil || !paid {
			continue
		}
		if ok, err := s.store.CreditBond(ctx, b.ID, time.Now().UTC()); err == nil && ok {
			mStake.WithLabelValues("bond_credited").Inc()
			credited++
		}
	}
	return credited
}

// watchBonds periodically credits paid bonds, so a bond counts — for the
// directory and for unbonding — whether or not anyone looks at its status.
func (s *Server) watchBonds(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if bonds, err := s.store.ListAwaitingBonds(ctx); err == nil {
				s.creditPaidBonds(ctx, bonds)
			}
		}
	}
}

// handleStakeStatus reports a node's stake, crediting its newly paid bonds
// first so an operator sees a payment land immediately.
func (s *Server) handleStakeStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.store.GetNode(ctx, chi.URLParam(r, "id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, "node not found")
		return
	}
	now := time.Now().UTC()
	bonds, err := s.store.ListBonds(ctx, n.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.creditPaidBonds(ctx, bonds) > 0 {
		bonds, _ = s.store.ListBonds(ctx, n.ID)
		n, _ = s.store.GetNode(ctx, n.ID) // crediting changed the stake
	}
	pending := make([]map[string]any, 0)
	for _, b := range bonds {
		if b.Status == "awaiting_payment" {
			pending = append(pending, map[string]any{
				"bond_id": b.ID, "amount_sats": b.AmountSats, "address": b.Quote.Address, "amount_label": b.Quote.AmountLabel,
			})
		}
	}
	unbondings, _ := s.store.ListUnbondings(ctx, n.ID)
	var unbonding, withdrawable int64
	for _, u := range unbondings {
		if u.ReleaseAt.After(now) {
			unbonding += u.AmountSats
		} else {
			withdrawable += u.AmountSats
		}
	}
	slashes, _ := s.store.ListSlashes(ctx, n.ID)
	var slashed int64
	for _, e := range slashes {
		slashed += e.SlashedSats
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":           n.ID,
		"bonded_sats":       n.StakeSats,
		"unbonding_sats":    unbonding,
		"withdrawable_sats": withdrawable,
		"slashed_sats":      slashed,
		"jailed":            n.JailedAt != nil,
		"eligible":          s.eligible(n),
		"min_stake_sats":    s.stake.MinSats,
		"pending_bonds":     pending,
		"slashes":           slashes,
	})
}

// handleStakeSlash accepts equivocation evidence from anyone. The descriptors
// must verify under the key the node registered, so a reporter cannot frame a
// node with descriptors they signed themselves.
func (s *Server) handleStakeSlash(w http.ResponseWriter, r *http.Request) {
	var body struct {
		A string `json:"descriptor_a"`
		B string `json:"descriptor_b"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	nodeID, err := staking.PeekNodeID(body.A)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "malformed descriptor")
		return
	}
	n, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "node not found")
		return
	}
	if len(n.EdPub) != ed25519.PublicKeySize {
		errJSON(w, http.StatusConflict, "node has no registered ed_pub")
		return
	}
	epoch, err := staking.CheckEquivocation(n.ID, n.EdPub, body.A, body.B)
	if err != nil {
		mStake.WithLabelValues("slash_rejected").Inc()
		errJSON(w, http.StatusBadRequest, "not valid equivocation evidence: "+err.Error())
		return
	}
	slashed, err := s.store.Slash(r.Context(), n.ID, epoch, s.stake.SlashPercent, body.A+"\n"+body.B, time.Now().UTC())
	switch {
	case errors.Is(err, ErrAlreadySlashed):
		errJSON(w, http.StatusConflict, "already slashed for this epoch")
		return
	case err != nil:
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AppendAudit(r.Context(), &AuditEntry{
		UserID: n.OwnerID, Action: "stake.slash", Detail: n.ID,
	})
	mStake.WithLabelValues("slashed").Inc()
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": n.ID, "epoch": epoch, "slashed_sats": slashed, "jailed": true,
	})
}

// handleStakeDevSettle pays a bond on the dev rail (local/CI only).
func (s *Server) handleStakeDevSettle(w http.ResponseWriter, r *http.Request) {
	dev, _ := s.rails["dev"].(*DevRail)
	if !s.devSettle || dev == nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		BondID string `json:"bond_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	b, err := s.store.GetBond(r.Context(), body.BondID)
	if err != nil || b.Rail != "dev" {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	dev.Settle(b.Quote.Address, uint64(b.AmountSats))
	writeJSON(w, http.StatusOK, map[string]string{"status": "settled"})
}

// eligible reports whether a node may be listed: enough bonded stake, not
// jailed, and a registered node key.
func (s *Server) eligible(n *Node) bool {
	return n.StakeSats >= s.stake.MinSats && n.JailedAt == nil && len(n.EdPub) == ed25519.PublicKeySize
}

// handleDirectory serves the signed consensus of eligible nodes. Clients verify
// it against the pinned authority key (client/src/directory.rs).
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if s.directory == nil {
		errJSON(w, http.StatusServiceUnavailable, "directory not configured")
		return
	}
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	doc := &directory.Document{
		Published:  now,
		ValidUntil: now.Add(time.Hour),
		Threshold:  1,
		Authorities: []directory.Authority{{
			Name: s.directory.Name, KeyTag: binary.BigEndian.Uint16(s.directory.Pub[:2]),
		}},
	}
	for i := range nodes {
		n := &nodes[i]
		if !s.eligible(n) {
			continue
		}
		mix := n.MixPubHex
		if mix == "" {
			mix = strings.Repeat("0", 64)
		}
		region := n.Region
		if region == "" {
			region = "ZZ" // ISO 3166 "unknown"
		}
		doc.Nodes = append(doc.Nodes, directory.Node{
			Name: n.Name, Address: n.Address, Role: n.Role, X25519Hex: mix,
			Ed25519Hex: hex.EncodeToString(n.EdPub), CapacityMbps: n.CapacityMbps, Region: region,
		})
	}
	if err := doc.Sign(s.directory.Name, s.directory.Signer); err != nil {
		errJSON(w, http.StatusInternalServerError, "directory signing failed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc.Encode())
}
