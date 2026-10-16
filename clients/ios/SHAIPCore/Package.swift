// swift-tools-version:6.0
// SHAIPCore: the Foundation-only core of the SHAIP iOS app — design tokens as data, the node and
// policy catalogue, telemetry maths, and the three render engines (mesh, globe, radar) ported from
// design/shaip-engine.js. No UIKit/SwiftUI, so it builds and tests on Linux as well as in Xcode:
//
//   swift test --package-path clients/ios/SHAIPCore
import PackageDescription

let package = Package(
    name: "SHAIPCore",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [.library(name: "SHAIPCore", targets: ["SHAIPCore"])],
    targets: [
        .target(name: "SHAIPCore"),
        .testTarget(name: "SHAIPCoreTests", dependencies: ["SHAIPCore"], resources: [.copy("Fixtures")]),
    ]
)
