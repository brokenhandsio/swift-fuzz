import Foundation

/// Turning libFuzzer's `-print_coverage=1` dump into something you would want
/// to read.
///
/// libFuzzer can report, per function, how many of its edges the corpus
/// reached. The raw form is one line per function — over a thousand of them for
/// a small library, two thirds of which are compiler-generated outlined
/// copy/destroy helpers with no source of their own — so this parses it, drops
/// the noise, and rolls the rest up by source file.
///
/// Edges are the headline number rather than functions. A function counts once
/// however large it is, so a file of many small accessors would otherwise
/// outweigh the one parser that actually matters.
enum Coverage {
    /// One function, as libFuzzer reported it.
    struct Function: Equatable {
        let name: String
        let file: String
        let line: Int
        let coveredEdges: Int
        let totalEdges: Int

        var isCovered: Bool { coveredEdges > 0 }
    }

    /// A source file's rolled-up totals.
    struct File {
        let name: String
        let functions: [Function]

        var coveredEdges: Int { functions.reduce(0) { $0 + $1.coveredEdges } }
        var totalEdges: Int { functions.reduce(0) { $0 + $1.totalEdges } }
        var coveredFunctions: Int { functions.count(where: \.isCovered) }
        var uncoveredEdges: Int { totalEdges - coveredEdges }

        /// Whether the fuzzer reached this file at all.
        ///
        /// The distinction the report turns on: a file at 7% is where more
        /// corpus or a dictionary pays off, while a file at 0% needs a target
        /// of its own — or belongs to no target at all.
        var isEntered: Bool { coveredEdges > 0 }

        /// Uncovered functions, in source order.
        var gaps: [Function] {
            functions.filter { !$0.isCovered }.sorted { $0.line < $1.line }
        }
    }

    /// Source files swift-fuzz itself contributes. They are linked into every
    /// fuzz binary and instrumented along with everything else, but they are
    /// not what anyone is trying to cover.
    ///
    /// Matching is by file name because that is all libFuzzer reports; a
    /// package with its own `FuzzTarget.swift` would be hidden too, which is a
    /// fair trade for keeping the harness out of every report.
    static let harnessFiles: Set<String> = [
        "FuzzRunner.swift",
        "FuzzTarget.swift",
        "FuzzTarget+Async.swift",
        "Fuzzable.swift",
        "FuzzedDataProvider.swift",
        // Emitted by FuzzTargetPlugin into the build directory.
        "FuzzEntryPoint.swift",
    ]

    /// libFuzzer's placeholder for code with no source location: thunks,
    /// outlined value-witness helpers, specialisations.
    static let compilerGenerated = "<compiler-generated>"

    // MARK: - Parsing

    /// Parses the `COVERED_FUNC`/`UNCOVERED_FUNC` lines out of a libFuzzer run.
    ///
    /// Anything else in the stream is ignored, so this is safe to hand the
    /// whole of standard error.
    static func parse(_ output: some StringProtocol) -> [Function] {
        output.split(separator: "\n").compactMap { parse(line: $0) }
    }

    /// Parses one line. Returns nil for any line that is not a function record.
    ///
    /// The shape is:
    ///
    ///     COVERED_FUNC: hits: 596 edges: 7/7 CBORParser.parse() CBORParser.swift:41
    ///
    /// The name can contain spaces (`outlined copy of CBOR`), so it is taken as
    /// everything between the edge counts and the trailing `file:line`.
    static func parse(line: some StringProtocol) -> Function? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("COVERED_FUNC:") || trimmed.hasPrefix("UNCOVERED_FUNC:") else {
            return nil
        }

        let fields = trimmed.split(separator: " ")
        guard fields.count >= 7, fields[1] == "hits:", fields[3] == "edges:" else { return nil }

        let edges = fields[4].split(separator: "/")
        guard edges.count == 2,
              let covered = Int(edges[0]),
              let total = Int(edges[1])
        else { return nil }

        // Trailing field is <file>:<line>. Split on the last colon: a path may
        // contain others, a line number may not.
        let location = fields[fields.count - 1]
        guard let colon = location.lastIndex(of: ":"),
              let lineNumber = Int(location[location.index(after: colon)...])
        else { return nil }

        let path = location[..<colon]
        // libFuzzer reports whatever the debug info holds, which is a bare file
        // name in some toolchains and an absolute path in others.
        let file = String(path.split(separator: "/").last ?? path)

        let name = fields[5..<(fields.count - 1)].joined(separator: " ")
        guard !name.isEmpty, !file.isEmpty else { return nil }

        return Function(
            name: name, file: file, line: lineNumber,
            coveredEdges: covered, totalEdges: total)
    }

    /// Whether a name is a mangled Swift symbol rather than something
    /// readable.
    ///
    /// macOS's symbolizer demangles as it goes; the one on Linux does not,
    /// because `$s` is Swift's mangling prefix and llvm-symbolizer only knows
    /// the Itanium C++ scheme. So the reports differ by platform and the Linux
    /// one needs a pass through `swift-demangle`.
    static func isMangled(_ name: some StringProtocol) -> Bool {
        name.hasPrefix("$s") || name.hasPrefix("_$s")
    }

    /// Replaces names using a demangling map, leaving anything absent from it
    /// alone.
    static func applying(_ readable: [String: String], to functions: [Function]) -> [Function] {
        guard !readable.isEmpty else { return functions }
        return functions.map { function in
            guard let name = readable[function.name] else { return function }
            return Function(
                name: name, file: function.file, line: function.line,
                coveredEdges: function.coveredEdges, totalEdges: function.totalEdges)
        }
    }

    /// The edge count libFuzzer reports on its own status lines.
    ///
    /// Deliberately not `-print_coverage`. That needs a symbolizer, which
    /// SwiftPM's macOS plugin sandbox will not let the sanitizer runtime
    /// launch — so a minimize that verified itself that way would start
    /// demanding `--disable-sandbox`. `cov:` appears on every `INITED`/`DONE`
    /// line and needs nothing. This is a count, not a set of edge identities;
    /// an unchanged count alone cannot prove identical coverage.
    ///
    /// Takes the last occurrence, which is the `DONE` line.
    static func edgeCount(in diagnostics: some StringProtocol) -> Int? {
        var result: Int?
        for line in diagnostics.split(separator: "\n") {
            guard let range = line.range(of: "cov: ") else { continue }
            let digits = line[range.upperBound...].prefix { $0.isNumber }
            if let value = Int(digits) { result = value }
        }
        return result
    }

    /// Whether a minimized corpus reaches less than the one it replaces.
    ///
    /// Missing counts are not evidence of loss. Callers must reject an
    /// unavailable measurement separately before replacing any inputs.
    static func lostCoverage(before: Int?, after: Int?) -> Bool {
        guard let before, let after else { return false }
        return after < before
    }

    // MARK: - Rolling up

    /// The result of rolling up a run: the files a report is about, and what
    /// was withheld from it.
    struct Summary {
        let files: [File]
        /// Files excluded for belonging to a dependency rather than to the code
        /// under test. Counted rather than dropped silently — a coverage figure
        /// that quietly changed its denominator would be worse than none.
        let dependencyFiles: Int
        let dependencyEdges: Int
    }

    /// Groups functions by source file, dropping what nobody can act on.
    ///
    /// Four things are excluded: swift-fuzz's own sources, functions attributed
    /// to `<compiler-generated>`, functions reported at line 0 — default
    /// argument generators, implicit closures and similar, which have a file
    /// but no line to point at — and, when `scope` is given, files outside the
    /// code under test.
    ///
    /// Files are ordered by how much they are *missing*, because the report
    /// exists to answer "where is the corpus not reaching?".
    static func summarize(_ functions: [Function], scope: Set<String>? = nil) -> Summary {
        var byFile: [String: [Function]] = [:]
        var dependencies: [String: Int] = [:]

        for function in functions {
            guard function.file != compilerGenerated,
                  function.line > 0,
                  !harnessFiles.contains(function.file)
            else { continue }

            if let scope, !scope.contains(function.file) {
                dependencies[function.file, default: 0] += function.totalEdges
                continue
            }
            byFile[function.file, default: []].append(function)
        }

        let files = byFile
            .map { File(name: $0.key, functions: $0.value) }
            .sorted { lhs, rhs in
                // Files the fuzzer actually entered come first. Ordering purely
                // by biggest gap buries them: URIParse reaches 2 of Vapor's 178
                // files, and the 176 it never entered all have larger gaps than
                // the one file the target exists to exercise.
                if lhs.isEntered != rhs.isEntered { return lhs.isEntered }
                // Then biggest gap; ties by name so the order is stable.
                return (lhs.uncoveredEdges, rhs.name) > (rhs.uncoveredEdges, lhs.name)
            }

        return Summary(
            files: files,
            dependencyFiles: dependencies.count,
            dependencyEdges: dependencies.values.reduce(0, +))
    }
}

// MARK: - Rendering

extension Coverage {
    /// The table, plus a headline total.
    /// How many never-entered files to list before collapsing the rest into a
    /// count. They are ordered largest-first, so the ones worth a target of
    /// their own are the ones that survive the cut.
    static let untouchedLimit = 10

    static func render(
        _ summary: Summary, target: String, inputs: String, full: Bool = false
    ) -> String {
        let entered = summary.files.filter(\.isEntered)
        let untouched = summary.files.filter { !$0.isEntered }
        let files = full ? summary.files : entered + untouched.prefix(untouchedLimit)
        let unlisted = summary.files.count - files.count
        guard !files.isEmpty else {
            // Everything filtered out is a different problem from nothing
            // reported, and has a different answer.
            if summary.dependencyFiles > 0 {
                return """

                    swift-fuzz: coverage for \(target)
                      \(inputs)

                    Every one of the \(summary.dependencyFiles) files reported belongs to a dependency
                    rather than to the code under test, so there is nothing to show.

                    That usually means this target only exercises a dependency. Pass
                    --include-dependencies to see them anyway.
                    """
            }
            return """

                swift-fuzz: coverage for \(target)
                  \(inputs)

                No instrumented source files were reported. The corpus may be empty,
                or the code under test may not have been instrumented.
                """
        }

        let edges = files.map { "\($0.coveredEdges)/\($0.totalEdges)" }
        let functions = files.map { "\($0.coveredFunctions)/\($0.functions.count)" }
        let nameWidth = max(4, files.map(\.name.count).max() ?? 4)
        let edgeWidth = max(5, edges.map(\.count).max() ?? 5)
        let functionWidth = max(9, functions.map(\.count).max() ?? 9)

        var lines = [
            "  " + "FILE".padded(to: nameWidth)
                + "  " + "EDGES".leftPadded(to: edgeWidth)
                + "       "
                + "FUNCTIONS".leftPadded(to: functionWidth)
        ]
        for (index, file) in files.enumerated() {
            lines.append(
                "  " + file.name.padded(to: nameWidth)
                    + "  " + edges[index].leftPadded(to: edgeWidth)
                    + "  " + percentage(file.coveredEdges, of: file.totalEdges).leftPadded(to: 5)
                    + "  " + functions[index].leftPadded(to: functionWidth)
            )
        }

        // Over every file in scope, not just the ones listed. Capping the
        // untouched tail must not quietly shrink the denominator.
        let coveredEdges = summary.files.reduce(0) { $0 + $1.coveredEdges }
        let totalEdges = summary.files.reduce(0) { $0 + $1.totalEdges }
        let fileWord = files.count == 1 ? "file" : "files"

        return """

            swift-fuzz: coverage for \(target)
              \(inputs)

            \(lines.joined(separator: "\n"))

              \(coveredEdges)/\(totalEdges) edges reached \
            (\(percentage(coveredEdges, of: totalEdges))) across \(summary.files.count) \(fileWord) \
            — \(entered.count) entered, \(untouched.count) never entered\
            \(withheld(summary, unlisted: unlisted))
            """
    }

    /// A note about what the scope filter kept out.
    ///
    /// Never silent: a reader comparing two runs has to be able to see that the
    /// denominator is the package rather than everything linked into the binary.
    private static func withheld(_ summary: Summary, unlisted: Int) -> String {
        var notes: [String] = []
        if unlisted > 0 {
            notes.append("\(unlisted) never-entered files not listed above")
        }
        if summary.dependencyFiles > 0 {
            let fileWord = summary.dependencyFiles == 1 ? "file" : "files"
            notes.append(
                "\(summary.dependencyFiles) dependency \(fileWord) "
                + "(\(summary.dependencyEdges) edges) excluded; --include-dependencies adds them")
        }
        guard !notes.isEmpty else { return "" }
        return "\n  " + notes.joined(separator: "\n  ")
    }

    /// Every uncovered function, grouped by file. This is the actionable half
    /// of the report and by far the longer one, so it is opt-in.
    static func renderGaps(_ files: [File]) -> String {
        let sections = files.compactMap { file -> String? in
            let gaps = file.gaps
            guard !gaps.isEmpty else { return nil }
            let entries = gaps.map { "      \($0.name)  \(file.name):\($0.line)" }
            return "    \(file.name)\n" + entries.joined(separator: "\n")
        }
        guard !sections.isEmpty else {
            return "\n  Every instrumented function was reached."
        }
        return "\n  Uncovered functions:\n" + sections.joined(separator: "\n")
    }

    static func percentage(_ part: Int, of whole: Int) -> String {
        guard whole > 0 else { return "-" }
        return "\(Int((Double(part) / Double(whole) * 100).rounded()))%"
    }
}

private extension String {
    func padded(to width: Int) -> String {
        count >= width ? self : self + String(repeating: " ", count: width - count)
    }

    func leftPadded(to width: Int) -> String {
        count >= width ? self : String(repeating: " ", count: width - count) + self
    }
}

// MARK: - Diagnostics

extension Coverage {
    /// What the sanitizer runtime prints when a sandbox blocks the spawn.
    static let symbolizerBlocked = "failed to spawn external symbolizer"

    /// What it prints when there is no symbolizer at the path it was given —
    /// including when it was given none and looked on PATH.
    static let symbolizerMissing = "external symbolizer"

    /// Whether libFuzzer failed to symbolize, for any reason.
    static func symbolizerFailed(in diagnostics: some StringProtocol) -> Bool {
        diagnostics.contains(symbolizerMissing)
    }

    /// Coverage needs addresses turned into function names, which the sanitizer
    /// runtime does by launching `llvm-symbolizer` as a child process. SwiftPM
    /// sandboxes command plugins on macOS and the sandbox denies that spawn —
    /// including for a symbolizer inside the toolchain — so there is nothing
    /// this plugin can set to make it work from inside. Linux has no plugin
    /// sandbox and is unaffected.
    /// Guidance for a run that died partway through.
    ///
    /// libFuzzer prints a `COVERAGE:` block even when it stops on a crashing
    /// input, and that block reflects almost nothing — every function comes
    /// back uncovered. Rendering it produces a confident, entirely wrong "your
    /// corpus reaches 0% of your package", which is worse than no report: it
    /// reads as a finding rather than as a failure.
    static func crashedMessage(target: String, status: Int32) -> String {
        """
        Coverage stopped at a crashing input (exit \(status)), so what libFuzzer \
        printed describes almost nothing and has been suppressed rather than shown.

        An input in Corpus/\(target) or Seeds/\(target) crashes this target. Find it with:

          swift package --allow-writing-to-package-directory fuzz \(target) --replay

        Fix the crash or remove the input, then ask for coverage again.
        """
    }

    /// Guidance for a symbolizer that could not be found at all.
    static func missingSymbolizerMessage(target: String) -> String {
        """
        Coverage needs llvm-symbolizer to turn addresses into function names, and \
        the sanitizer runtime could not find one.

        swift-fuzz normally points it at the toolchain's copy automatically. If you \
        are here, that lookup failed — set it explicitly:

          ASAN_SYMBOLIZER_PATH=$(xcrun -f llvm-symbolizer) \\
            swift package --allow-writing-to-package-directory fuzz \(target) --coverage

        On Linux it is usually at /usr/bin/llvm-symbolizer.
        """
    }

    static func sandboxMessage(target: String) -> String {
        """
        Coverage needs llvm-symbolizer, and SwiftPM's plugin sandbox will not let \
        the sanitizer runtime launch it.

        Re-run outside the sandbox:

          swift package --disable-sandbox --allow-writing-to-package-directory \\
            fuzz \(target) --coverage

        This affects macOS only; on Linux there is no plugin sandbox.
        """
    }
}
