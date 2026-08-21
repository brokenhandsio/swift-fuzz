import Foundation

// MARK: - Running

extension Coverage {
    /// Runs the corpus once with coverage reporting on, and returns the report.
    ///
    /// `-runs=0` means every input is executed exactly once and nothing is
    /// mutated, so the answer describes the corpus as it stands rather than
    /// whatever a fuzzing session happened to wander into.
    static func run(
        binary: URL,
        layout: Layout,
        passthrough: [String],
        listUncovered: Bool,
        demangler: URL?,
        workDirectory: URL
    ) throws -> String {
        let corpusCount = countInputs(layout.corpus)
        let seedCount = layout.hasSeeds ? countInputs(layout.seeds) : 0
        guard corpusCount + seedCount > 0 else {
            throw FuzzError("""
                There are no inputs to measure: both Corpus/\(layout.target) and \
                Seeds/\(layout.target) are empty.
                Run the fuzzer first, or add seeds.
                """)
        }

        var arguments = [
            "-runs=0",
            "-print_coverage=1",
            "-detect_leaks=0",
            // A corpus input that crashes should still be saved rather than
            // just aborting the report.
            "-artifact_prefix=\(layout.crashes.path)/",
        ]
        arguments += passthrough
        arguments += layout.inputDirectories

        var environment = ProcessInfo.processInfo.environment
        environment["FUZZ_TARGET"] = layout.target
        #if !os(macOS)
        environment["SWIFT_BACKTRACE"] = "enable=no"
        #endif

        let (status, diagnostics) = try Process.captureDiagnostics(
            binary, arguments, environment: environment,
            currentDirectory: layout.packageDirectory)

        let functions = parse(diagnostics)
        guard !functions.isEmpty else {
            // The common failure by far, and it is not the user's fault.
            if diagnostics.contains(symbolizerFailure) {
                throw FuzzError(sandboxMessage(target: layout.target))
            }
            throw FuzzError("""
                libFuzzer reported no coverage data (exit \(status)).

                \(status == 0
                    ? "The build may lack debug info, or llvm-symbolizer may not be on PATH."
                    : "An input in the corpus looks to have crashed before the report was printed.")

                Its output was:
                \(tail(diagnostics))
                """)
        }

        // Linux reports Swift symbols mangled; macOS does not. Doing this
        // before rolling up means the sort and the listing both see real names.
        let readable = Demangle.names(
            functions.map(\.name), using: demangler, workDirectory: workDirectory)

        let inputs = seedCount > 0
            ? "\(corpusCount) corpus inputs, \(seedCount) seeds"
            : "\(corpusCount) corpus inputs"
        let files = summarize(applying(readable, to: functions))
        return render(files, target: layout.target, inputs: inputs)
            + (listUncovered ? "\n" + renderGaps(files) : "")
    }

    private static func countInputs(_ directory: URL) -> Int {
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: [.isRegularFileKey])) ?? []
        return contents.count {
            (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
        }
    }

    /// The last few lines, for an error message. The full dump can run to
    /// thousands of lines and the interesting part is always at the end.
    private static func tail(_ output: String, lines: Int = 12) -> String {
        output.split(separator: "\n").suffix(lines)
            .map { "  \($0)" }
            .joined(separator: "\n")
    }
}
