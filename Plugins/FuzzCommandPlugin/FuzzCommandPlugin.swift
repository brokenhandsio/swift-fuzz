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

        let discovery = Discovery(context: context) { product in
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
                binary: binary, layout: layout, path: path,
                workDirectory: context.pluginWorkDirectoryURL, passthrough: options.passthrough)
            print("""

                swift-fuzz: minimized \(path) in place
                  \(result.bytesBefore) bytes -> \(result.bytesAfter) bytes
                """)
            return
        }

        if case .minimizeCorpus = options.mode {
            let result = try Minimize.run(
                binary: binary, layout: layout, workDirectory: context.pluginWorkDirectoryURL)
            print("""

                swift-fuzz: minimized Corpus/\(target)
                  \(result.filesBefore) files, \(result.bytesBefore) bytes
                  \(result.filesAfter) files, \(result.bytesAfter) bytes
                Seeds/\(target) was not modified.
                """)
            return
        }

        let status = try run(binary: binary, options: options, layout: layout)
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

    private func run(binary: URL, options: Arguments, layout: Layout) throws -> Int32 {
        var arguments: [String] = []

        // Ours first so anything the user passes overrides it.
        arguments.append("-artifact_prefix=\(layout.crashes.path)/")
        arguments.append("-detect_leaks=0")
        // Without this libFuzzer ignores 1- and 2-byte comparisons, which is
        // most byte-oriented format dispatch (CBOR major types, magic numbers).
        arguments.append("-use_value_profile=1")
        if let dictionary = layout.dictionary {
            arguments.append("-dict=\(dictionary.path)")
        }

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
        case .minimizeCorpus, .minimizeCrash, .list:
            // Handled before this point; neither uses the standard run path.
            preconditionFailure("\(options.mode) does not use the standard run path")
        }

        var environment = ProcessInfo.processInfo.environment
        environment["FUZZ_TARGET"] = layout.target
        #if !os(macOS)
        // Swift's crash handler otherwise runs instead of libFuzzer's, which
        // means the crashing input is never written and the exit code is a
        // bare signal. Findings would be visible in the log and lost on disk.
        environment["SWIFT_BACKTRACE"] = "enable=no"
        #endif

        return try Process.stream(
            binary,
            arguments,
            environment: environment,
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

/// Where a target's seeds, corpus, crashes and dictionary live.
struct Layout {
    let packageDirectory: URL
    let target: String

    /// Hand-written starting inputs. libFuzzer is given this directory *after*
    /// the corpus, which makes it read-only: new discoveries go to the first
    /// directory on the command line and never here.
    ///
    /// The separation is what keeps curated inputs safe from `-merge=1`, which
    /// rewrites the directory it minimizes and would otherwise delete any seed
    /// whose coverage is reachable some other way. Specification vectors are
    /// documentation as much as coverage; losing them loses the provenance.
    let seeds: URL

    /// The working corpus: libFuzzer's accumulated discoveries. Written to.
    let corpus: URL
    let crashes: URL
    let dictionary: URL?

    init(packageDirectory: URL, target: String) throws {
        self.packageDirectory = packageDirectory
        self.target = target
        self.seeds = packageDirectory.appending(path: "Seeds/\(target)")
        self.corpus = packageDirectory.appending(path: "Corpus/\(target)")
        self.crashes = packageDirectory.appending(path: "Crashes/\(target)")
        let dictionary = packageDirectory.appending(path: "Dictionaries/\(target).dict")
        self.dictionary = FileManager.default.fileExists(atPath: dictionary.path) ? dictionary : nil
    }

    func create() throws {
        // Seeds are deliberately not created: an empty directory would be noise
        // in every package that does not curate any.
        for directory in [corpus, crashes] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    /// Directories holding inputs to read, in the order libFuzzer should see
    /// them: the writable corpus first, then any read-only seeds.
    var inputDirectories: [String] {
        var directories = [corpus.path]
        if hasSeeds { directories.append(seeds.path) }
        return directories
    }

    /// Whether any seed inputs are present. An empty or missing directory is
    /// not passed, because libFuzzer treats a directory it cannot read as an
    /// error rather than as "no inputs".
    var hasSeeds: Bool {
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: seeds.path)) ?? []
        return !contents.isEmpty
    }

    /// Whether any crashing inputs have been saved for this target.
    var hasCrashArtefacts: Bool {
        !crashArtefacts().isEmpty
    }

    /// Crash artefacts, oldest first.
    func crashArtefacts() -> [URL] {
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: crashes,
            includingPropertiesForKeys: [.contentModificationDateKey]
        )) ?? []
        return contents.sorted {
            let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return left < right
        }
    }
}
