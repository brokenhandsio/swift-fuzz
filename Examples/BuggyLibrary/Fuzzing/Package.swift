// swift-tools-version: 6.3
import PackageDescription

// The same settings swift-fuzz itself uses. Applied here so the examples show
// that a fuzz harness works in a package with strict memory safety enabled —
// the interesting case, since the harness receives an unsafe buffer.
let extraSettings: [SwiftSetting] = [
    .strictMemorySafety(),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("InternalImportsByDefault"),
]

let package = Package(
    name: "Fuzzing",
    platforms: [.macOS(.v26)],
    dependencies: [
        // The library under test, and swift-fuzz itself. Note that the `package:`
        // label for a path dependency is the *directory* name, not the name in
        // its Package.swift.
        .package(path: "../"),
        .package(path: "../../../"),
    ],
    targets: [
        // The executable is the C shim; the fuzz logic lives in the library.
        .executableTarget(
            name: "BuggyParse",
            dependencies: ["BuggyParseTarget"],
            path: "FuzzTargets/BuggyParseShim"
        ),
        .target(
            name: "BuggyParseTarget",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "BuggyLibrary", package: "BuggyLibrary"),
            ],
            path: "FuzzTargets/BuggyParse",
            swiftSettings: extraSettings,
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
        .executableTarget(
            name: "BuggyMulti",
            dependencies: ["BuggyMultiTarget"],
            path: "FuzzTargets/BuggyMultiShim"
        ),
        .target(
            name: "BuggyMultiTarget",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "BuggyLibrary", package: "BuggyLibrary"),
            ],
            path: "FuzzTargets/BuggyMulti",
            swiftSettings: extraSettings,
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
    ]
)
