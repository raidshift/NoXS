// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "NoXS",

    platforms: [
        .macOS(.v12),
    ],

    products: [
        .library(
            name: "NoXS",
            targets: ["NoXS"]
        ),
    ],

    dependencies: [
        .package(
            url: "https://github.com/raidshift/phc-winner-argon2", from: "1.0.0"
        ),
    ],

    targets: [
        .target(
            name: "NoXS",
            dependencies: [.product(name: "argon2", package: "phc-winner-argon2")],
            path: "Sources/Lib"
        ),
        .testTarget(
            name: "Test",
            dependencies: ["NoXS"],
            path: "Sources/Test"
        ),
        .executableTarget(
            name: "noxscli",
            dependencies: ["NoXS"],
            path: "Sources/CLI"
        ),
    ]
)
