import Foundation
import PackagePlugin

/// `swift package fuzz-init <Name>` — adds a fuzz target to this package.
///
/// This runs inside the `Fuzzing` package, not the library under test: the
/// whole point of the nested layout is that the main package never depends on
/// swift-fuzz, so a plugin cannot run there. Creating the `Fuzzing` package
/// itself is a one-off documented in the README; this handles every target
/// after that.
@main
struct FuzzInitPlugin: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        var target: String?
        var standalone = false

        var index = arguments.startIndex
        while index < arguments.endIndex {
            switch arguments[index] {
            case "--standalone":
                standalone = true
            case "--paired":
                standalone = false
            case "--help", "-h":
                throw FuzzInitError(usage)
            case let argument where argument.hasPrefix("-"):
                throw FuzzInitError("Unknown option \"\(argument)\".\n\n\(usage)")
            case let argument where target == nil:
                target = argument
            case let argument:
                throw FuzzInitError("Unexpected argument \"\(argument)\".\n\n\(usage)")
            }
            index += 1
        }

        guard let target else { throw FuzzInitError(usage) }
        try Scaffold.validate(name: target)

        let root = context.package.directoryURL
        let harnessDirectory = root.appending(path: "FuzzTargets/\(target)")
        let shimDirectory = root.appending(path: "FuzzTargets/\(target)Shim")
        let seedsDirectory = root.appending(path: "Seeds/\(target)")

        // Refuse rather than overwrite: the harness is the one file here the
        // user will have edited.
        for directory in [harnessDirectory, shimDirectory] where exists(directory) {
            throw FuzzInitError("""
                "\(directory.lastPathComponent)" already exists under FuzzTargets/.
                Delete it first, or pick another name.
                """)
        }

        var written: [String] = []
        try write(Scaffold.harness(target: target),
                  to: harnessDirectory.appending(path: "\(target).swift"), noting: &written, root: root)
        if !standalone {
            try write(Scaffold.shim,
                      to: shimDirectory.appending(path: "shim.c"), noting: &written, root: root)
        }
        // Seeds are optional but the directory is worth creating: an empty one
        // is invisible to git, so it gets a .gitkeep to make the convention
        // discoverable rather than something you read about later.
        try write("", to: seedsDirectory.appending(path: ".gitkeep"), noting: &written, root: root)

        print("""
            Created:
            \(written.map { "  \($0)" }.joined(separator: "\n"))

            Add to Package.swift, in `targets:`

            \(Scaffold.manifestStanza(target: target, standalone: standalone)
                .split(separator: "\n").map { "    \($0)" }.joined(separator: "\n"))

            Then edit FuzzTargets/\(target)/\(target).swift and run:

                swift package --allow-writing-to-package-directory fuzz \(target) --time 60
            """)
    }

    private func exists(_ url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    private func write(_ contents: String, to url: URL, noting written: inout [String], root: URL) throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        written.append(url.path.replacingOccurrences(of: root.path + "/", with: ""))
    }

    private let usage = """
        USAGE: swift package --allow-writing-to-package-directory fuzz-init <Name> [--standalone]

        Adds a fuzz target to this Fuzzing package: a harness stub, the C entry-point
        shim, and a Seeds directory. Prints the Package.swift stanza to paste in.

        OPTIONS:
          --paired       C shim plus a Swift library. Works on every supported
                         toolchain. The default.
          --standalone   A single Swift executable target, no shim. Requires Swift 6.4
                         or later; see "Two shapes" in swift-fuzz's README.
        """
}
