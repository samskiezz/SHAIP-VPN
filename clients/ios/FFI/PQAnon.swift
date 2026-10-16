import Foundation
import PQAnonFFI

// Small helpers over the Rust core's C ABI (ffi/include/pqanon.h), shared by
// the app (enrollment) and the tunnel extension (the tunnel itself).

/// Take ownership of a string the library returned: copy it and free it.
func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
    guard let p else { return nil }
    defer { pqanon_string_free(p) }
    return String(cString: p)
}

/// The Rust core's version.
var pqanonVersion: String { String(cString: pqanon_version()) }

/// An error message from the Rust core.
struct CoreError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
