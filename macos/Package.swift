// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "VeilDNS",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "VeilDNS", targets: ["VeilDNS"]),
        .executable(name: "VeilDNSProxyHelper", targets: ["VeilDNSProxyHelper"]),
        .executable(name: "VeilDNSIntegrationChecks", targets: ["VeilDNSIntegrationChecks"]),
    ],
    targets: [
        .target(name: "VeilDNSCore"),
        .executableTarget(name: "VeilDNS", dependencies: ["VeilDNSCore"]),
        .executableTarget(name: "VeilDNSProxyHelper", dependencies: ["VeilDNSCore"]),
        .executableTarget(name: "VeilDNSIntegrationChecks", dependencies: ["VeilDNSCore"]),
        .testTarget(name: "VeilDNSCoreTests", dependencies: ["VeilDNSCore"]),
    ],
    swiftLanguageModes: [.v6]
)
