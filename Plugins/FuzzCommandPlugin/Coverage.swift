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

    // MARK: - Rolling up

    /// Groups functions by source file, dropping the harness and anything with
    /// no source of its own.
    ///
    /// Three things are excluded, all of them code nobody can go and write a
    /// test for: swift-fuzz's own sources, functions attributed to
    /// `<compiler-generated>`, and functions reported at line 0 — default
    /// argument generators, implicit closures and similar, which have a file
    /// but no line to point at. What remains is the code the package author
    /// wrote, which is what a coverage figure should describe.
    ///
    /// Files are ordered by how much they are *missing*, because the report
    /// exists to answer "where is the corpus not reaching?".
    static func summarize(_ functions: [Function]) -> [File] {
        var byFile: [String: [Function]] = [:]
        for function in functions {
            guard function.file != compilerGenerated,
                  function.line > 0,
                  !harnessFiles.contains(function.file)
            else { continue }
            byFile[function.file, default: []].append(function)
        }
        return byFile
            .map { File(name: $0.key, functions: $0.value) }
            .sorted {
                // Biggest gap first; ties by name so the order is stable.
                ($0.uncoveredEdges, $1.name) > ($1.uncoveredEdges, $0.name)
            }
    }
}

// MARK: - Rendering

extension Coverage {
    /// The table, plus a headline total.
    static func render(_ files: [File], target: String, inputs: String) -> String {
        guard !files.isEmpty else {
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

        let coveredEdges = files.reduce(0) { $0 + $1.coveredEdges }
        let totalEdges = files.reduce(0) { $0 + $1.totalEdges }
        let fileWord = files.count == 1 ? "file" : "files"

        return """

            swift-fuzz: coverage for \(target)
              \(inputs)

            \(lines.joined(separator: "\n"))

              \(coveredEdges)/\(totalEdges) edges reached \
            (\(percentage(coveredEdges, of: totalEdges))) across \(files.count) \(fileWord)
            """
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
    /// What the sanitizer runtime prints when it cannot launch a symbolizer.
    static let symbolizerFailure = "failed to spawn external symbolizer"

    /// Coverage needs addresses turned into function names, which the sanitizer
    /// runtime does by launching `llvm-symbolizer` as a child process. SwiftPM
    /// sandboxes command plugins on macOS and the sandbox denies that spawn —
    /// including for a symbolizer inside the toolchain — so there is nothing
    /// this plugin can set to make it work from inside. Linux has no plugin
    /// sandbox and is unaffected.
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
