// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Fuzzing",
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
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
    ]
)
