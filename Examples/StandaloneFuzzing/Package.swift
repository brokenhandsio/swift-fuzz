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

// The *standalone* shape: one Swift executable target, no C shim, no paired
// library. FuzzTargetPlugin sees an executable target and generates libFuzzer's
// `LLVMFuzzerInitialize` and `LLVMFuzzerTestOneInput` straight into it.
//
// Requires Swift 6.4 or later. On 6.3.x this fails with an explanatory error,
// because SwiftPM's `native` build system renames a Swift executable's `main`
// and that collides with the `main` libFuzzer's runtime supplies. Use the
// paired shape in ../BuggyLibrary/Fuzzing there.
//
// This would normally live at `YourRepo/Fuzzing/`, exactly like the paired
// example. It sits beside the library here only so both shapes can be shown
// against one library under test.
let package = Package(
    name: "StandaloneFuzzing",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "../BuggyLibrary"),
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "BuggyParse",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "BuggyLibrary", package: "BuggyLibrary"),
            ],
            path: "FuzzTargets/BuggyParse",
            swiftSettings: extraSettings,
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        )
    ]
)
