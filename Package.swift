// swift-tools-version: 6.3
import PackageDescription

// The Lifetimes/SuppressedAssociatedTypes features swift-cbor enables are for its
// `Span`-based parser; nothing here needs them. The rest are the same set.
let extraSettings: [SwiftSetting] = [
    .strictMemorySafety(),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("InternalImportsByDefault"),
]

let package = Package(
    name: "swift-fuzz",
    // v26 throughout, which is what lets the API be expressed in terms of `Span`
    // and removes the need to annotate the concurrency entry points.
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .macCatalyst(.v26),
        .visionOS(.v26),
        .watchOS(.v26),
    ],
    products: [
        .library(name: "Fuzzing", targets: ["Fuzzing"]),
        .plugin(name: "FuzzTargetPlugin", targets: ["FuzzTargetPlugin"]),
        .plugin(name: "FuzzCommandPlugin", targets: ["FuzzCommandPlugin"]),
        .plugin(name: "FuzzInitPlugin", targets: ["FuzzInitPlugin"]),
        .plugin(name: "OSSFuzzPlugin", targets: ["OSSFuzzPlugin"]),
    ],
    targets: [
        .target(name: "Fuzzing", swiftSettings: extraSettings),
        .plugin(
            name: "FuzzTargetPlugin",
            capability: .buildTool()
        ),
        .plugin(
            name: "FuzzCommandPlugin",
            capability: .command(
                intent: .custom(verb: "fuzz", description: "Build and run a libFuzzer fuzz target."),
                permissions: [
                    .writeToPackageDirectory(reason: "swift-fuzz writes discovered inputs to Corpus/ and crashing inputs to Crashes/.")
                ]
            )
        ),
        .plugin(
            name: "FuzzInitPlugin",
            capability: .command(
                intent: .custom(verb: "fuzz-init", description: "Add a fuzz target to this package."),
                permissions: [
                    .writeToPackageDirectory(reason: "swift package fuzz-init creates the fuzz target's source files.")
                ]
            )
        ),
        .plugin(
            name: "OSSFuzzPlugin",
            capability: .command(
                intent: .custom(
                    verb: "generate-oss-fuzz-script",
                    description: "Set up an OSS-Fuzz project with a pinned Swift toolchain."
                ),
                permissions: [
                    .writeToPackageDirectory(reason: "generate-oss-fuzz-script writes the OSS-Fuzz integration files.")
                ]
            )
        ),
        .testTarget(name: "FuzzingTests", dependencies: ["Fuzzing"], swiftSettings: extraSettings),
        // Plugin targets cannot be imported, so the command plugin's argument
        // parser is symlinked into this target and compiled a second time.
        // Same file on disk, so the two copies cannot drift.
        .testTarget(name: "FuzzCommandPluginTests"),
        .testTarget(name: "FuzzInitPluginTests"),
        .testTarget(name: "OSSFuzzPluginTests"),
    ]
)

// MARK: - Development-only dependencies

// DocC documentation plugin. CI sets SWIFT_FUZZ_DOCC=1 when building the docs
// archive. Gated so that consumers of this package never resolve it.
if Context.environment["SWIFT_FUZZ_DOCC"] != nil {
    package.dependencies.append(
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.0")
    )
}
