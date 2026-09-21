// Build the actual getting-started snippets against this checkout.
import Foundation

struct CheckFailure: Error, CustomStringConvertible {
    let description: String
}

func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw CheckFailure(description: message) }
}

func run(_ arguments: [String], in directory: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["swift"] + arguments
    process.currentDirectoryURL = directory
    try process.run()
    process.waitUntilExit()
    try require(process.terminationStatus == 0, "swift \(arguments.joined(separator: " ")) failed")
}

let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let readme = try String(contentsOf: repository.appendingPathComponent("README.md"), encoding: .utf8)
let fences = try NSRegularExpression(pattern: "```swift\\n(.*?)```", options: .dotMatchesLineSeparators)
let blocks = fences.matches(in: readme, range: NSRange(readme.startIndex..., in: readme)).map {
    String(readme[Range($0.range(at: 1), in: readme)!])
}
guard var manifest = blocks.first(where: { $0.hasPrefix("// swift-tools-version:") }),
      let targets = blocks.first(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("targets: [") })
else { throw CheckFailure(description: "could not locate the README's manifest and targets") }

// Test the current source without waiting for the next release to exist.
let dependency = try NSRegularExpression(
    pattern: #"\.package\(url: "https://github.com/brokenhandsio/swift-fuzz.git", from: "[^"]+"\)"#
)
let matches = dependency.matches(in: manifest, range: NSRange(manifest.startIndex..., in: manifest))
try require(matches.count == 1, "could not locate the README's swift-fuzz dependency")
manifest.replaceSubrange(Range(matches[0].range, in: manifest)!, with: ".package(path: \(String(reflecting: repository.path)))")

let manager = FileManager.default
let temporary = manager.temporaryDirectory.appendingPathComponent("swift-fuzz-readme-\(UUID().uuidString)")
defer { try? manager.removeItem(at: temporary) }
let library = temporary.appendingPathComponent("YourRepo")
let sources = library.appendingPathComponent("Sources/YourLibrary")
try manager.createDirectory(at: sources, withIntermediateDirectories: true)
try """
// swift-tools-version: 6.3
import PackageDescription
let package = Package(
    name: "YourRepo",
    platforms: [.macOS(.v26)],
    products: [.library(name: "YourLibrary", targets: ["YourLibrary"])],
    targets: [.target(name: "YourLibrary")]
)
""".write(to: library.appendingPathComponent("Package.swift"), atomically: true, encoding: .utf8)
try "public enum YourLibrary {}\n".write(to: sources.appendingPathComponent("YourLibrary.swift"), atomically: true, encoding: .utf8)
let fuzzing = library.appendingPathComponent("Fuzzing")
try manager.createDirectory(at: fuzzing, withIntermediateDirectories: true)
let package = fuzzing.appendingPathComponent("Package.swift")
try manifest.write(to: package, atomically: true, encoding: .utf8)

var packageOptions = ["package", "--allow-writing-to-package-directory"]
#if os(macOS)
// Match the fuzz command's nested SwiftPM builds on macOS.
packageOptions.insert("--disable-sandbox", at: 1)
#endif
try run(packageOptions + ["fuzz-init", "JSONParsing"], in: fuzzing)
try require(manifest.contains("targets: []"), "README's initial manifest should have no targets")
try manifest.replacingOccurrences(of: "targets: []", with: targets.trimmingCharacters(in: .whitespacesAndNewlines))
    .write(to: package, atomically: true, encoding: .utf8)
// Compile the library target without needing Xcode to ship libFuzzer.
try run(["build", "--target", "JSONParsingTarget"], in: fuzzing)
if CommandLine.arguments.contains("--run") {
    try run(packageOptions + ["fuzz", "JSONParsing", "--replay"], in: fuzzing)
}
