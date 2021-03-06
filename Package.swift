// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "NEWireGuard",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "NEWireGuard",
            targets: ["NEWireGuard"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "NEWireGuard",
            dependencies: ["Blake2s", "ChaCha20", "Poly1305", "Curve25519"]),
        .target(
            name: "Blake2s",
            dependencies: []),
        .target(
            name: "ChaCha20",
            dependencies: []),
        .target(
            name: "Poly1305",
            dependencies: []),
        .target(
            name: "Curve25519",
            dependencies: []),
        .target(
            name: "CommonCryptoDigests",
            dependencies: []),
        .target(
            name: "Blake2sTestVectors",
            dependencies: []),
        .testTarget(
            name: "NEWireGuardTests",
            dependencies: ["NEWireGuard"]),
        .testTarget(
            name: "Blake2sTests",
            dependencies: ["NEWireGuard", "Blake2sTestVectors"]),
        .testTarget(
            name: "ChaCha20Poly1305Tests",
            dependencies: ["NEWireGuard"]),
        .testTarget(
            name: "Curve25519Tests",
            dependencies: ["NEWireGuard"]),
        .testTarget(
            name: "HKDFTests",
            dependencies: ["NEWireGuard", "CommonCryptoDigests"]),
        .testTarget(
            name: "TAI64NTests",
            dependencies: ["NEWireGuard"]),
        .testTarget(
            name: "IntegerExtensionsTests",
            dependencies: ["NEWireGuard"]),
    ]
)
