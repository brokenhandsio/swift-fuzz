// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "OSSFuzzValidation",
    platforms: [.macOS(.v26)],
    dependencies: [.package(path: "../../")],
    targets: [
        .executableTarget(name: "Combined", dependencies: ["CombinedHarness"], path: "Targets/CombinedShim"),
        .target(
            name: "CombinedHarness", dependencies: [.product(name: "Fuzzing", package: "swift-fuzz")],
            path: "Targets/Combined", resources: [.copy("marker.txt")],
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
        .executableTarget(name: "OtherProduct", dependencies: ["SingleHarness"], path: "Targets/SingleShim"),
        .target(
            name: "SingleHarness", dependencies: [.product(name: "Fuzzing", package: "swift-fuzz")],
            path: "Targets/Single", plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
    ]
)
