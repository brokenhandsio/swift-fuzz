// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-fuzz",
    products: [
        .library(name: "Fuzzing", targets: ["Fuzzing"]),
        .plugin(name: "FuzzTargetPlugin", targets: ["FuzzTargetPlugin"]),
        .plugin(name: "FuzzCommandPlugin", targets: ["FuzzCommandPlugin"]),
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
        .testTarget(name: "FuzzingTests", dependencies: ["Fuzzing"]),
    ]
)
