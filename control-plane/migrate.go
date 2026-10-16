package main

import (
	"context"
	_ "embed"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// embeddedSchema is the canonical schema, compiled into the binary so the
// control plane can provision its own tables at startup. It is kept identical
// to db/schema.sql (enforced by schema_embed_test.go).
//
//go:embed schema.sql
var embeddedSchema string

// applySchema runs the embedded schema against the pool. Every statement is
// idempotent (CREATE ... IF NOT EXISTS), so this is safe to run on every boot
// and turns "the migrations never ran" into "the schema is always present,
// however Postgres was provisioned". pgx uses the simple query protocol when a
// query carries no arguments, so the multi-statement script executes in one
// round trip.
//
// On a database from before the no-personal-data rule, the schema drops the
// columns and rows that held customer data. Postgres leaves dropped and
// updated values in the table files until a table is rewritten, so the tables
// that held them are rewritten here too: the data is then gone from the disk,
// not just hidden. (Backups and WAL archives taken before the upgrade still
// hold it; docs/privacy-policy.md says to destroy them.)
func applySchema(ctx context.Context, pool *pgxpool.Pool) error {
	var legacy bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		 WHERE (table_name = 'users' AND column_name IN ('email', 'identity_id'))
		    OR (table_name = 'audit_log' AND column_name = 'ip'))`).Scan(&legacy)
	if _, err := pool.Exec(ctx, embeddedSchema); err != nil {
		return err
	}
	if legacy {
		// VACUUM can't run inside the schema's implicit transaction.
		for _, table := range []string{"users", "audit_log", "devices", "enroll_tokens", "api_keys", "pay_orders", "spent_tokens"} {
			if _, err := pool.Exec(ctx, "VACUUM FULL "+table); err != nil {
				log.Printf("WARNING: could not rewrite %s (%v): removed personal data may remain in its files until it is vacuumed", table, err)
			}
		}
		log.Printf("removed personal data left by an older version (emails, addresses, connection and domain records) and rewrote the tables that held it")
	}
	return nil
}
