// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-fuzz",
    products: [
        .library(name: "Fuzzing", targets: ["Fuzzing"]),
        .plugin(name: "FuzzTargetPlugin", targets: ["FuzzTargetPlugin"]),
        .plugin(name: "FuzzCommandPlugin", targets: ["FuzzCommandPlugin"]),
        .plugin(name: "FuzzInitPlugin", targets: ["FuzzInitPlugin"]),
    ],
    targets: [
        .target(name: "Fuzzing"),
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
        .testTarget(name: "FuzzingTests", dependencies: ["Fuzzing"]),
        // Plugin targets cannot be imported, so the command plugin's argument
        // parser is symlinked into this target and compiled a second time.
        // Same file on disk, so the two copies cannot drift.
        .testTarget(name: "FuzzCommandPluginTests"),
        .testTarget(name: "FuzzInitPluginTests"),
    ]
)
