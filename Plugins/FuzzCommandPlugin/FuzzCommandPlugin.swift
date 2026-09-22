import Foundation
import PackagePlugin

/// `swift package fuzz` — builds a fuzz target with instrumentation and runs it.
///
/// The point of this plugin is that the user never types a compiler flag. It
/// owns the whole story: instrumenting the code under test (which reaches the
/// parent package because `otherSwiftcFlags` apply graph-wide), linking the
/// libFuzzer runtime, laying out corpus and crash directories, and turning a
/// libFuzzer crash into a non-zero exit with a copy-pasteable reproducer.
@main
struct FuzzCommandPlugin: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        let options = try Arguments.parse(arguments)
        // Before the instrumented build, which is slow and whose failure mode
        // for a toolchain without libFuzzer is unreadable.
        try Preflight.check(context: context)

        // The sanitizer runtime looks for llvm-symbolizer on PATH only, and a
        // toolchain chosen with TOOLCHAINS or xcrun usually is not on it. We
        // already know which toolchain we are building with, so hand it over.
        let symbolizer = try? context.tool(named: "llvm-symbolizer").url

        // Before the build, not after it. Instrumenting a package the size of
        // Vapor takes tens of minutes, and a coverage report that cannot be
        // symbolized is worth nothing — so discovering the problem afterwards
        // throws away the whole wait.
        if case .coverage = options.mode {
            let environment = FuzzEnvironment.make(target: nil, symbolizer: symbolizer)
            guard FuzzEnvironment.hasSymbolizer(environment) else {
                throw FuzzError(Coverage.missingSymbolizerMessage(target: options.target ?? "<target>"))
            }
        }

        let products = context.package.products.compactMap { $0 as? ExecutableProduct }.map(\.name).sorted()
        let discovery = Discovery(products: products) { product in
            try build(target: product, options: options, context: context)
        }

        if case .list = options.mode {
            print(discovery.listing(try discovery.all()))
            return
        }

        let resolved = try discovery.resolve(requested: options.target)
        let binary = resolved.binary
        let target = resolved.target
        let layout = try Layout(packageDirectory: context.package.directoryURL, target: target)
        try layout.create()

        if case .minimizeCrash(let path) = options.mode {
            let result = try Minimize.crash(
                binary: binary, layout: layout, path: path, symbolizer: symbolizer,
                passthrough: options.passthrough)
            print("""

                swift-fuzz: minimized \(path) in place
                  \(result.bytesBefore) bytes -> \(result.bytesAfter) bytes
                """)
            return
        }

        if case .minimizeCorpus = options.mode {
            let result = try Minimize.run(
                binary: binary, layout: layout, symbolizer: symbolizer,
                passthrough: options.passthrough)
            print("""

                swift-fuzz: minimized Corpus/\(target)
                  \(result.filesBefore) files, \(result.bytesBefore) bytes
                  \(result.filesAfter) files, \(result.bytesAfter) bytes
                Seeds/\(target) was not modified.
                """)
            return
        }

        if case .coverage = options.mode {
            print(try Coverage.run(
                binary: binary, layout: layout,
                passthrough: options.passthrough, listUncovered: options.listUncovered,
                // Everything linked into the binary is instrumented, which for a
                // package with real dependencies means the report is mostly
                // other people's code. Default to the package under test.
                scope: options.includeDependencies
                    ? nil
                    : CoverageScope.filesUnderTest(context.package),
                // Absent on some installs; the report is merely less readable.
                demangler: try? context.tool(named: "swift-demangle").url,
                symbolizer: symbolizer,
                workDirectory: context.pluginWorkDirectoryURL))
            return
        }

        let status = try run(
            binary: binary, options: options, layout: layout, symbolizer: symbolizer)
        try report(status: status, layout: layout, target: target, options: options)
    }

    // MARK: - Build

    private func build(target: String, options: Arguments, context: PluginContext) throws -> URL {
        var parameters = PackageManager.BuildParameters()
        parameters.configuration = options.release ? .release : .debug
        parameters.echoLogs = true
        parameters.otherSwiftcFlags = [
            "-sanitize=\(options.sanitizers)",
            // Suppress the Swift `main` so libFuzzer's own can be used. Safe
            // here because the executable target is pure C — see the shim.
            "-parse-as-library",
            "-g",
        ]

        let result = try packageManager.build(.product(target), parameters: parameters)

        guard result.succeeded else {
            if FuzzerRuntime.lacksFuzzerSupport(buildLog: result.logText) {
                throw FuzzError(FuzzerRuntime.missingToolchainMessage)
            }
            throw FuzzError(FuzzerRuntime.buildFailureMessage)
        }

        guard let artifact = result.builtArtifacts.first(where: { $0.kind == .executable }) else {
            throw FuzzError("Build succeeded but produced no executable for \"\(target)\".")
        }
        return artifact.url
    }

    // MARK: - Run

    private func run(
        binary: URL, options: Arguments, layout: Layout, symbolizer: URL?
    ) throws -> Int32 {
        // Ours first so anything the user passes overrides it.
        var arguments = FuzzerArguments.defaults(layout: layout)

        switch options.mode {
        case .fuzz:
            arguments += options.passthrough
            // Corpus first: libFuzzer writes newly discovered inputs to the
            // first directory it is given, and treats the rest as read-only.
            arguments += layout.inputDirectories
        case .replay:
            arguments.append("-runs=0")
            arguments += options.passthrough
            // Corpus first (libFuzzer only writes to the first directory, and
            // -runs=0 means it writes nothing anyway), then any saved crashes.
            // Previously-fixed bugs are the regressions most worth catching, so
            // a replay that skipped Crashes/ would miss the point.
            arguments += layout.inputDirectories
            if layout.hasCrashArtefacts {
                arguments.append(layout.crashes.path)
            }
        case .reproduce(let path):
            arguments += options.passthrough
            arguments.append(path)
        case .minimizeCorpus, .minimizeCrash, .list, .coverage:
            // Handled before this point; neither uses the standard run path.
            preconditionFailure("\(options.mode) does not use the standard run path")
        }

        return try Process.stream(
            binary,
            arguments,
            environment: FuzzEnvironment.make(target: layout.target, symbolizer: symbolizer),
            currentDirectory: layout.packageDirectory
        )
    }

    // MARK: - Reporting

    private func report(status: Int32, layout: Layout, target: String, options: Arguments) throws {
        guard status != 0 else { return }

        let artefacts = layout.crashArtefacts()
        if let newest = artefacts.last {
            let relative = newest.path.replacingOccurrences(
                of: layout.packageDirectory.path + "/", with: "")
            print("""

                swift-fuzz: \(target) crashed. Input saved to:
                  \(relative)

                Reproduce it with:
                  swift package --allow-writing-to-package-directory fuzz \(target) --reproduce \(relative)
                """)
        }
        // Crashes are the product, but they still have to fail the build.
        throw FuzzError("\(target) exited with status \(status).")
    }
}
