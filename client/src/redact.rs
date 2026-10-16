//! Log output for the server daemons that cannot carry an IP address.
//!
//! The daemons don't log clients at all: no line names a client's address,
//! identity or device (see the server's `core` module). This is the backstop
//! for what code review can't promise, such as an error string from a library
//! or a log line added later that happens to carry an address. Every line the
//! daemon logs passes through [`redact_addrs`], which replaces each IPv4 or
//! IPv6 address in it, with its port or zone, before the line is written. The
//! control plane's log writer does the same (control-plane/logredact.go).

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};

/// What an address is replaced with.
pub const REDACTED: &str = "[addr]";

/// `text` with every IP address in it replaced by [`REDACTED`].
///
/// The text is split into runs of the characters an address and port are made
/// of (hex digits, `.` and `:`), and a run that parses as an address, or
/// `address:port`, is replaced. A run that doesn't is searched for an IPv4
/// address glued to other characters (`id7192.0.2.1:80`, or one after a
/// terminal colour code). Parsing, not pattern matching, decides, so times
/// ("12:34:56"), versions ("1.22.3") and hex ids are left alone.
pub fn redact_addrs(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if is_addr_byte(bytes[i]) {
            while i < bytes.len() && is_addr_byte(bytes[i]) {
                i += 1;
            }
            out.push_str(&redact_run(&text[start..i]));
        } else {
            while i < bytes.len() && !is_addr_byte(bytes[i]) {
                i += 1;
            }
            out.push_str(&text[start..i]);
        }
    }
    out
}

fn is_addr_byte(c: u8) -> bool {
    c.is_ascii_hexdigit() || c == b'.' || c == b':'
}

fn redact_run(run: &str) -> String {
    // Allow for sentence punctuation after the address ("…:5432: refused").
    let core = run.trim_end_matches(['.', ':']);
    if is_addr(core) {
        return format!("{REDACTED}{}", &run[core.len()..]);
    }
    // An IPv4 address (and port) inside the run.
    let b = run.as_bytes();
    let mut out = String::with_capacity(run.len());
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
            i += 1;
        }
        let candidate = run[start..i].trim_end_matches('.');
        if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
            let mut end = start + candidate.len();
            if b.get(end) == Some(&b':') && b.get(end + 1).is_some_and(u8::is_ascii_digit) {
                end += 1;
                while end < b.len() && b[end].is_ascii_digit() {
                    end += 1;
                }
            }
            out.push_str(REDACTED);
            i = end;
        } else {
            out.push_str(&run[start..i]);
        }
    }
    out
}

fn is_addr(s: &str) -> bool {
    !s.is_empty() && (s.parse::<IpAddr>().is_ok() || s.parse::<SocketAddr>().is_ok())
}

/// A `tracing` writer that buffers one log event and writes it to stderr with
/// every address redacted.
pub struct RedactingWriter {
    buf: Vec<u8>,
}

impl Write for RedactingWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let line = redact_addrs(&String::from_utf8_lossy(&self.buf));
            self.buf.clear();
            io::stderr().write_all(line.as_bytes())?;
        }
        Ok(())
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Makes a [`RedactingWriter`] per log event.
#[derive(Clone, Copy, Default)]
pub struct Redacting;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Redacting {
    type Writer = RedactingWriter;
    fn make_writer(&'a self) -> RedactingWriter {
        RedactingWriter { buf: Vec::new() }
    }
}

/// Install the daemon log subscriber: `RUST_LOG` (default `default_filter`),
/// to stderr, through the address redactor.
pub fn init_server_logging(default_filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into()),
        )
        .with_ansi(false)
        .with_writer(Redacting)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_redacted_and_nothing_else() {
        for (input, want) in [
            ("dial 10.0.0.5:5432: connection refused", "dial [addr]: connection refused"),
            ("peer=203.0.113.7 sent junk", "peer=[addr] sent junk"),
            ("from [2001:db8::1]:443 and fe80::1%eth0.", "from [[addr]]:443 and [addr]%eth0."),
            ("http://192.0.2.10:18082/json_rpc", "http://[addr]/json_rpc"),
            ("::ffff:198.51.100.4 mapped", "[addr] mapped"),
            ("src=198.51.100.7:40000 next=203.0.113.9:8443", "src=[addr] next=[addr]"),
            // Glued to other characters, as terminal colour codes leave it.
            ("\x1b[2m=\x1b[0m127.0.0.1:9100 up", "\x1b[2m=\x1b[0m[addr] up"),
            ("id7a192.0.2.1:80,", "id7a[addr],"),
            ("2026-10-16T12:34:56.789Z  INFO listening on :443", "2026-10-16T12:34:56.789Z  INFO listening on :443"),
            ("rustls 0.23.12 cert fp ab:cd:ef deadbeef01", "rustls 0.23.12 cert fp ab:cd:ef deadbeef01"),
            ("rate 0.5 of 1.25, 42 peers, oid 1.2.3.4.5", "rate 0.5 of 1.25, 42 peers, oid 1.2.3.4.5"),
            ("naïve ünïcode stays", "naïve ünïcode stays"),
        ] {
            assert_eq!(redact_addrs(input), want, "{input}");
        }
    }

    #[test]
    fn the_writer_redacts_whole_events() {
        let mut w = RedactingWriter { buf: Vec::new() };
        w.write_all(b"relaying cell from 198.51.").unwrap();
        w.write_all(b"100.7:40000\n").unwrap();
        // Split writes are joined before redaction (the event is buffered).
        assert_eq!(redact_addrs(&String::from_utf8_lossy(&w.buf)), "relaying cell from [addr]\n");
        w.buf.clear();
    }
}
