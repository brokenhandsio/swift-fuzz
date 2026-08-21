import Foundation
import PackagePlugin

/// Working out which source files a coverage report should be about.
///
/// libFuzzer instruments and reports on everything linked into the binary,
/// which for a package with real dependencies means the report is mostly other
/// people's code. Fuzzing Vapor's URI parser produces `44/628536 edges reached
/// (0%) across 1455 files`, and because the report leads with the biggest gaps,
/// the first page is NIO, swift-collections and swift-configuration. Nothing
/// the author could act on appears at all.
enum CoverageScope {
    /// The file names belonging to the code under test: the fuzz package
    /// itself, and every package reached from it that is checked out locally
    /// rather than fetched.
    ///
    /// `PackageOrigin` draws the line exactly. A package you point at with a
    /// path is one you are working on — the parent package a `Fuzzing/`
    /// directory sits inside is the canonical case — while anything from a
    /// repository or registry is a dependency you are merely linking.
    ///
    /// Matching is by file name because that is all libFuzzer reports. Two
    /// packages that both contain a `Extensions.swift` would let the
    /// dependency's copy through; over-inclusion is the safe direction, and it
    /// beats showing all 1455 files.
    static func filesUnderTest(_ package: Package) -> Set<String> {
        var seen: Set<Package.ID> = []
        var names: Set<String> = []

        func walk(_ package: Package) {
            guard seen.insert(package.id).inserted, isUnderTest(package) else { return }
            for target in package.targets {
                guard let module = target as? SourceModuleTarget else { continue }
                for file in module.sourceFiles {
                    names.insert(file.url.lastPathComponent)
                }
            }
            for dependency in package.dependencies { walk(dependency.package) }
        }

        walk(package)
        return names
    }

    private static func isUnderTest(_ package: Package) -> Bool {
        switch package.origin {
        case .root, .local: true
        case .repository, .registry: false
        @unknown default: false
        }
    }
}
