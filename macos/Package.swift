// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "VeilDNS",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "VeilDNS", targets: ["VeilDNS"]),
        .executable(name: "VeilDNSProxyHelper", targets: ["VeilDNSProxyHelper"]),
    ],
    targets: [
        .target(name: "VeilDNSCore"),
        .executableTarget(name: "VeilDNS", dependencies: ["VeilDNSCore"]),
        .executableTarget(name: "VeilDNSProxyHelper", dependencies: ["VeilDNSCore"]),
        .testTarget(name: "VeilDNSCoreTests", dependencies: ["VeilDNSCore"]),
    ],
    swiftLanguageModes: [.v6]
)
