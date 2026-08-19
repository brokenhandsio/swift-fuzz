// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "BuggyLibrary",
    products: [.library(name: "BuggyLibrary", targets: ["BuggyLibrary"])],
    targets: [.target(name: "BuggyLibrary")]
)
