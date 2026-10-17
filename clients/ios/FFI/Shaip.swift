import Foundation
import ShaipFFI

// Small helpers over the Rust core's C ABI (ffi/include/shaip.h), shared by
// the app (enrollment) and the tunnel extension (the tunnel itself).

/// Take ownership of a string the library returned: copy it and free it.
func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
    guard let p else { return nil }
    defer { shaip_string_free(p) }
    return String(cString: p)
}

/// The Rust core's version.
var shaipVersion: String { String(cString: shaip_version()) }

/// An error message from the Rust core.
struct CoreError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
