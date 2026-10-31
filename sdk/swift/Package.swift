// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HXDataLock",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
    ],
    products: [
        .library(name: "HXDataLock", targets: ["HXDataLock"]),
        .executable(name: "hxdl-swift", targets: ["hxdl-swift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.12.0"),
    ],
    targets: [
        .target(
            name: "HXDataLock",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            linkerSettings: [
                .linkedLibrary("stdc++", .when(platforms: [.linux])),
            ]
        ),
        .executableTarget(
            name: "hxdl-swift",
            dependencies: ["HXDataLock"],
            linkerSettings: [
                .linkedLibrary("stdc++", .when(platforms: [.linux])),
            ]
        ),
        .testTarget(
            name: "HXDataLockTests",
            dependencies: ["HXDataLock"],
            linkerSettings: [
                .linkedLibrary("stdc++", .when(platforms: [.linux])),
            ]
        ),
    ]
)
