// swift-tools-version:5.9
// FFIInterop: compiles the app's own C-ABI Swift (FFI/*.swift, symlinked in) against
// ffi/include/pqanon.h + module.modulemap, links the Rust core (target/release/libpqanon_ffi.a),
// and drives the call sequence the tunnel extension uses against a live pqanond. It proves the
// Swift ↔ Rust boundary on Linux, where the NetworkExtension/SwiftUI parts cannot be built.
//
//   cargo build --release -p pqanon-ffi && swift run --package-path clients/ios/FFIInterop FFIInterop …
//   (scripts/test-all.sh runs it as part of the iOS stage)
import Foundation
import PackageDescription

let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../..").standardized.path

let package = Package(
    name: "FFIInterop",
    dependencies: [.package(path: "../SHAIPCore")],
    targets: [
        .systemLibrary(name: "PQAnonFFI", path: "PQAnonFFI"),
        .executableTarget(
            name: "FFIInterop",
            dependencies: ["PQAnonFFI", .product(name: "SHAIPCore", package: "SHAIPCore")],
            linkerSettings: [
                // The static archive, as the app links it (not the .so beside it).
                .unsafeFlags(["\(repo)/target/release/libpqanon_ffi.a"]),
                .linkedLibrary("dl"), .linkedLibrary("util"), .linkedLibrary("rt"), .linkedLibrary("m"),
            ]),
    ]
)
