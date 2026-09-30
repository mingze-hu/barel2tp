// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "BareL2TPApp",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "BareL2TPApp", targets: ["BareL2TPApp"]),
    ],
    targets: [
        .executableTarget(name: "BareL2TPApp"),
        .testTarget(
            name: "BareL2TPAppTests",
            dependencies: ["BareL2TPApp"]
        ),
    ]
)
