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
    name: "BuggyLibrary",
    platforms: [.macOS(.v26)],
    products: [.library(name: "BuggyLibrary", targets: ["BuggyLibrary"])],
    targets: [.target(name: "BuggyLibrary", swiftSettings: extraSettings)]
)
