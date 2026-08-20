import Foundation
import PackagePlugin

/// `swift package generate-oss-fuzz-script` — writes an OSS-Fuzz integration
/// for this package.
///
/// The target list is read from the package rather than typed by hand, so a
/// script regenerated after adding a target is correct by construction. That is
/// the whole point: a stale `build.sh` fails inside OSS-Fuzz's builder, where
/// the feedback loop is slow.
@main
struct OSSFuzzPlugin: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        var repository: String?
        var outputName = "OSSFuzz"

        var index = arguments.startIndex
        while index < arguments.endIndex {
            switch arguments[index] {
            case "--repository":
                index += 1
                guard index < arguments.endIndex else {
                    throw OSSFuzzError("--repository requires a URL.")
                }
                repository = arguments[index]
            case "--output":
                index += 1
                guard index < arguments.endIndex else {
                    throw OSSFuzzError("--output requires a directory name.")
                }
                outputName = arguments[index]
            case "--help", "-h":
                throw OSSFuzzError(Self.usage)
            case let argument:
                throw OSSFuzzError("Unexpected argument \"\(argument)\".\n\n\(Self.usage)")
            }
            index += 1
        }

        let targets = context.package.products
            .compactMap { $0 as? ExecutableProduct }
            .map(\.name)
            .sorted()
        guard !targets.isEmpty else {
            throw OSSFuzzError("""
                This package declares no fuzz targets, so there is nothing to build.
                Add one with: swift package fuzz-init <Name>
                """)
        }

        // The fuzzing package's own directory name, and the repository checkout
        // it sits inside — build.sh has to cd into one from the other.
        let fuzzingDirectory = context.package.directoryURL.lastPathComponent

        // Derived from the git remote unless given. `--repository` stays as an
        // override for a repo with no remote, several remotes, or one that is
        // not where OSS-Fuzz should clone from.
        let resolved = repository ?? detectRepository(in: context.package.directoryURL)
        guard let resolved else {
            throw OSSFuzzError("""
                Could not work out which repository OSS-Fuzz should clone: this package has no
                usable git remote. Pass one:

                  swift package --allow-writing-to-package-directory \\
                    generate-oss-fuzz-script --repository https://github.com/you/your-repo
                """)
        }
        let checkoutName = OSSFuzzTemplates.checkoutName(for: resolved)

        let output = context.package.directoryURL.appending(path: outputName)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

        var written: [String] = []
        try write(OSSFuzzTemplates.buildScript(packageDirectory: fuzzingDirectory, targets: targets),
                  to: output.appending(path: "build.sh"), executable: true, noting: &written)
        try write(OSSFuzzTemplates.projectYAML(repository: resolved),
                  to: output.appending(path: "project.yaml"), noting: &written)
        try write(OSSFuzzTemplates.dockerfile(repository: resolved, checkoutName: checkoutName),
                  to: output.appending(path: "Dockerfile"), noting: &written)
        try write(OSSFuzzTemplates.readme(targets: targets, directory: fuzzingDirectory),
                  to: output.appending(path: "README.md"), noting: &written)

        print("""
            Wrote an OSS-Fuzz integration for \(targets.count) target\(targets.count == 1 ? "" : "s") \
            (\(targets.joined(separator: ", "))):
            \(written.map { "  \(outputName)/\($0)" }.joined(separator: "\n"))

            Repository: \(resolved)\(repository == nil ? " (from the git remote)" : "")

            See \(outputName)/README.md for how to test it locally and submit it.
            """)
    }

    /// Reads `origin` from the enclosing git repository, if there is one.
    ///
    /// `git` is asked rather than the filesystem parsed: the fuzzing package is
    /// nested inside the repository, and git already knows how to walk up.
    private func detectRepository(in directory: URL) -> String? {
        guard let output = try? Process.captureOutput(
            URL(fileURLWithPath: "/usr/bin/env"),
            ["git", "-C", directory.path, "remote", "get-url", "origin"]
        ) else { return nil }
        return OSSFuzzTemplates.normalizeRemote(output)
    }

    private func write(
        _ contents: String, to url: URL, executable: Bool = false, noting written: inout [String]
    ) throws {
        try contents.write(to: url, atomically: true, encoding: .utf8)
        if executable {
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }
        written.append(url.lastPathComponent)
    }

    static let usage = """
        USAGE: swift package --allow-writing-to-package-directory generate-oss-fuzz-script [options]

        Writes build.sh, project.yaml, Dockerfile and a README for submitting this
        package to OSS-Fuzz. The fuzz target list is read from the package, so
        regenerate after adding or renaming one.

        OPTIONS:
          --repository <url>   The repository OSS-Fuzz should clone. Defaults to this
                               package's git `origin`, converted to an https URL.
          --output <dir>       Directory to write into. Default: OSSFuzz
        """
}

struct OSSFuzzError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

extension Process {
    /// Runs a tool and returns its standard output, or nil if it failed.
    static func captureOutput(_ executable: URL, _ arguments: [String]) throws -> String? {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}
