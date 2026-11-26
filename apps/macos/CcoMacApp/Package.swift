// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CcoMacApp",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "CcoCore", targets: ["CcoCore"]),
        .executable(name: "CcoMacApp", targets: ["CcoMacApp"])
    ],
    targets: [
        .target(
            name: "CCcoFfi",
            path: "Sources/CCcoFfi",
            publicHeadersPath: "include"
        ),
        .target(
            name: "CcoCore",
            dependencies: ["CCcoFfi"],
            path: "Sources/CcoCore",
            linkerSettings: [
                .linkedLibrary("cco_ffi"),
                .linkedLibrary("iconv"),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation")
            ]
        ),
        .executableTarget(
            name: "CcoMacApp",
            dependencies: ["CcoCore"],
            path: "Sources/CcoMacApp"
        ),
        .testTarget(
            name: "CcoCoreTests",
            dependencies: ["CcoCore"],
            path: "Tests/CcoCoreTests"
        )
    ]
)
