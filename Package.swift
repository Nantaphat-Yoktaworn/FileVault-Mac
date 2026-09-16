// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "FileVaultMac",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .executable(name: "FileVaultMac", targets: ["FileVaultMacApp"])
    ],
    targets: [
        .target(name: "VaultCore"),
        .executableTarget(name: "FileVaultMacApp", dependencies: ["VaultCore"]),
        .testTarget(name: "VaultCoreTests", dependencies: ["VaultCore"])
    ]
)
