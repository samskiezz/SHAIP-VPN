package main

import (
	"context"
	_ "embed"

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
func applySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, embeddedSchema)
	return err
}
