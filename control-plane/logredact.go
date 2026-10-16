package main

// The control plane does not log client addresses: there is no request logger,
// and no log line formats one. redactingWriter is the backstop for what code
// review can't promise, such as an error string from a library or a log line
// added later that happens to carry an address. Every line the process logs
// passes through it, and each IPv4 or IPv6 address in the line, with its port
// or zone, is replaced before the line is written.

import (
	"bytes"
	"io"
	"net/netip"
	"sync"
)

const redactedAddr = "[addr]"

type redactingWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (r *redactingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.w.Write(redactAddrs(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// redactAddrs returns text with every IP address in it replaced. It splits the
// text into runs of the bytes an address, port or zone can contain, and
// replaces each run that parses as an address. Parsing, not pattern matching,
// decides, so times ("12:34:56") and versions ("go1.22.3") are left alone.
func redactAddrs(text []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(text); {
		if !isAddrByte(text[i]) {
			out.WriteByte(text[i])
			i++
			continue
		}
		j := i
		for j < len(text) && isAddrByte(text[j]) {
			j++
		}
		out.Write(redactRun(text[i:j]))
		i = j
	}
	return out.Bytes()
}

func isAddrByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c == '.' || c == ':' || c == '%'
}

// redactRun replaces run if it is an address (or address:port), allowing for
// sentence punctuation after it ("refused 10.0.0.5:5432: connect").
func redactRun(run []byte) []byte {
	core := bytes.TrimRight(run, ".:")
	if isAddr(string(core)) {
		return append([]byte(redactedAddr), run[len(core):]...)
	}
	return run
}

func isAddr(s string) bool {
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParseAddrPort(s)
	return err == nil
}
