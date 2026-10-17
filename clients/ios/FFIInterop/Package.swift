// swift-tools-version:5.9
// FFIInterop: compiles the app's own C-ABI Swift (FFI/*.swift, symlinked in) against
// ffi/include/shaip.h + module.modulemap, links the Rust core (target/release/libshaip_ffi.a),
// and drives the call sequence the tunnel extension uses against a live shaipd. It proves the
// Swift ↔ Rust boundary on Linux, where the NetworkExtension/SwiftUI parts cannot be built.
//
//   cargo build --release -p shaip-ffi && swift run --package-path clients/ios/FFIInterop FFIInterop …
//   (scripts/test-all.sh runs it as part of the iOS stage)
import Foundation
import PackageDescription

let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../..").standardized.path

let package = Package(
    name: "FFIInterop",
    dependencies: [.package(path: "../SHAIPCore")],
    targets: [
        .systemLibrary(name: "ShaipFFI", path: "ShaipFFI"),
        .executableTarget(
            name: "FFIInterop",
            dependencies: ["ShaipFFI", .product(name: "SHAIPCore", package: "SHAIPCore")],
            linkerSettings: [
                // The static archive, as the app links it (not the .so beside it).
                .unsafeFlags(["\(repo)/target/release/libshaip_ffi.a"]),
                .linkedLibrary("dl"), .linkedLibrary("util"), .linkedLibrary("rt"), .linkedLibrary("m"),
            ]),
    ]
)
