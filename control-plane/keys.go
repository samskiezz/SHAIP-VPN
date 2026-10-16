package main

// Signing-key resolution. Every control-plane signing key is resolved the same
// way, so an operator moves a key into an HSM by setting one variable:
//
//  1. <NAME>_SIGNER — an explicit keystore spec (file:, env:, pkcs11:, ephemeral);
//  2. a legacy base64-seed variable, where one exists (TOKEN_SIGNING_KEY);
//  3. $KEY_DIR/<name>.key — a key file under the shared key directory, created
//     0600 on first boot;
//  4. otherwise an ephemeral key, with a warning. That is fine for dev, but
//     anything that pins the public key breaks on every restart: tunnel servers
//     pin the CRL key, and clients pin the enrollment and device-CA keys.

import (
	"crypto"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"pqanon/control-plane/keystore"
)

// resolveSigner returns the signer for the key `name`, plus a log-safe
// description of where it came from.
func resolveSigner(name, specVar, legacySeedVar string) (crypto.Signer, string, error) {
	spec := os.Getenv(specVar)
	switch {
	case spec != "":
	case legacySeedVar != "" && os.Getenv(legacySeedVar) != "":
		spec = "env:" + legacySeedVar
	case os.Getenv("KEY_DIR") != "":
		spec = "file:" + filepath.Join(os.Getenv("KEY_DIR"), name+".key")
	default:
		spec = "ephemeral"
	}
	s, err := keystore.Open(spec)
	if err != nil {
		return nil, "", fmt.Errorf("%s key (%s): %w", name, keystore.Describe(spec), err)
	}
	if spec == "ephemeral" {
		log.Printf("WARNING: the %s signing key is ephemeral and will change on restart — set %s (or KEY_DIR) to a key file or an HSM", name, specVar)
	}
	return s, keystore.Describe(spec), nil
}
