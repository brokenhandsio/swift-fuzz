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
        scope: Set<String>?,
        demangler: URL?,
        symbolizer: URL?,
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

        let environment = FuzzEnvironment.make(target: layout.target, symbolizer: symbolizer)

        // Before the run, not after. Replaying a large corpus takes minutes —
        // forty of them on Vapor — and a report that cannot be symbolized is
        // worth nothing, so finding out at the end wastes the whole thing.
        guard FuzzEnvironment.hasSymbolizer(environment) else {
            throw FuzzError(missingSymbolizerMessage(target: layout.target))
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

        let (status, diagnostics) = try Process.captureDiagnostics(
            binary, arguments, environment: environment,
            currentDirectory: layout.packageDirectory)

        // Before looking at what was printed. A run that died partway through
        // still prints a coverage block, and it is one where nothing is
        // covered — so a crashing corpus input would otherwise be reported as
        // a package with no coverage at all. Vapor's URIComponents did exactly
        // that: a confident `0/44680 edges reached (0%)` that meant nothing.
        guard status == 0 else {
            throw FuzzError(crashedMessage(target: layout.target, status: status))
        }

        let functions = parse(diagnostics)
        guard !functions.isEmpty else {
            // Two different symbolizer failures with two different fixes.
            if diagnostics.contains(symbolizerBlocked) {
                throw FuzzError(sandboxMessage(target: layout.target))
            }
            if symbolizerFailed(in: diagnostics) {
                throw FuzzError(missingSymbolizerMessage(target: layout.target))
            }
            throw FuzzError("""
                libFuzzer reported no coverage data (exit \(status)).

                The build may lack debug info.

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
        let summary = summarize(applying(readable, to: functions), scope: scope)
        return render(summary, target: layout.target, inputs: inputs, full: listUncovered)
            + (listUncovered ? "\n" + renderGaps(summary.files) : "")
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
