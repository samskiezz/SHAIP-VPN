//go:build !js

package main

import (
	"os"
	"strings"
	"testing"
)

// normalizeSQL drops comment lines and blank lines and collapses whitespace so
// two schema files are compared on their statements, not their headers.
func normalizeSQL(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		b.WriteString(strings.Join(strings.Fields(t), " "))
		b.WriteString("\n")
	}
	return b.String()
}

// TestEmbeddedSchemaMatchesDbSchema guards against the embedded schema (applied
// by the running binary) drifting from db/schema.sql (mounted by docker-compose
// into the database init dir). If they diverge, one deployment path would get a
// different schema than the other — so this fails the build.
func TestEmbeddedSchemaMatchesDbSchema(t *testing.T) {
	disk, err := os.ReadFile("../db/schema.sql")
	if err != nil {
		t.Fatalf("read db/schema.sql: %v", err)
	}
	if normalizeSQL(string(disk)) != normalizeSQL(embeddedSchema) {
		t.Fatal("control-plane/schema.sql and db/schema.sql have diverged — keep the statements identical")
	}
}
