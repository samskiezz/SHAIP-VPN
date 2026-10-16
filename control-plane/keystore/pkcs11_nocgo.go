//go:build !cgo

package keystore

import (
	"crypto"
	"errors"
)

// The PKCS#11 backend loads the vendor's module through cgo. A static
// CGO_ENABLED=0 build (the default container image) cannot do that, so it
// rejects pkcs11: specs clearly instead of failing at link time.
func openPKCS11(pkcs11Config) (crypto.Signer, error) {
	return nil, errors.New("pkcs11: this binary was built without cgo; rebuild with CGO_ENABLED=1 on an image that ships your HSM's PKCS#11 module")
}
