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
// text into runs of the characters an address and port are made of (hex
// digits, '.' and ':') and replaces each run that parses as an address or
// address:port. A run that doesn't is searched for an IPv4 address glued to
// other characters ("id7a192.0.2.1:80"). Parsing, not pattern matching,
// decides, so times ("12:34:56"), versions ("go1.22.3") and hex ids are left
// alone. The Rust daemons use the same rules (client/src/redact.rs).
func redactAddrs(text []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(text); {
		j := i
		if isAddrByte(text[i]) {
			for j < len(text) && isAddrByte(text[j]) {
				j++
			}
			out.Write(redactRun(text[i:j]))
		} else {
			for j < len(text) && !isAddrByte(text[j]) {
				j++
			}
			out.Write(text[i:j])
		}
		i = j
	}
	return out.Bytes()
}

func isAddrByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':'
}

// redactRun replaces run if it is an address (allowing for sentence
// punctuation after it: "refused 10.0.0.5:5432: connect"), or else any IPv4
// address (and port) inside it.
func redactRun(run []byte) []byte {
	core := bytes.TrimRight(run, ".:")
	if isAddr(string(core)) {
		return append([]byte(redactedAddr), run[len(core):]...)
	}
	var out []byte
	for i := 0; i < len(run); {
		if run[i] < '0' || run[i] > '9' {
			out = append(out, run[i])
			i++
			continue
		}
		j := i
		for j < len(run) && (run[j] >= '0' && run[j] <= '9' || run[j] == '.') {
			j++
		}
		cand := bytes.TrimRight(run[i:j], ".")
		if a, err := netip.ParseAddr(string(cand)); err == nil && a.Is4() {
			end := i + len(cand)
			if end+1 < len(run) && run[end] == ':' && run[end+1] >= '0' && run[end+1] <= '9' {
				end++
				for end < len(run) && run[end] >= '0' && run[end] <= '9' {
					end++
				}
			}
			out = append(out, redactedAddr...)
			i = end
		} else {
			out = append(out, run[i:j]...)
			i = j
		}
	}
	return out
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
