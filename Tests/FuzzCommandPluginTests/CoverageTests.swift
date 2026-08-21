import Testing

// `Coverage.swift` here is a symlink to the command plugin's copy — see the note
// in ArgumentsTests.swift for why. Only the pure half is linked: parsing,
// rolling up and rendering. Running the binary lives in Coverage+Run.swift,
// which needs PackagePlugin types the test target cannot see.

@Suite("Coverage reporting")
struct CoverageTests {
    // A verbatim sample of what libFuzzer -print_coverage=1 writes to stderr.
    static let sample = """
        #2611	DONE   cov: 521 ft: 2900 corp: 710/60Kb lim: 1712 exec/s: 0 rss: 125Mb
        COVERAGE:
        COVERED_FUNC: hits: 596 edges: 7/7 CBORParser.parse() CBORParser.swift:41
        COVERED_FUNC: hits: 12 edges: 3/9 CBORParser.readHead() CBORParser.swift:88
        UNCOVERED_FUNC: hits: 0 edges: 0/11 CBOR.subscript.getter CBOR+Accessors.swift:10
        UNCOVERED_FUNC: hits: 0 edges: 0/7 CBOREncoder.encode(_:) CBOREncoder.swift:20
        COVERED_FUNC: hits: 596 edges: 7/7 outlined copy of CBOR /<compiler-generated>:0
        UNCOVERED_FUNC: hits: 0 edges: 0/4 FuzzRunner.reportStall() FuzzRunner.swift:120
        UNCOVERED_FUNC: hits: 0 edges: 0/2 default argument 0 of f(_:) CBOREncoder.swift:0
        """

    // MARK: Parsing

    @Test("A covered function is parsed field by field")
    func parseCovered() throws {
        let function = try #require(Coverage.parse(
            line: "COVERED_FUNC: hits: 596 edges: 7/7 CBORParser.parse() CBORParser.swift:41"))
        #expect(function.name == "CBORParser.parse()")
        #expect(function.file == "CBORParser.swift")
        #expect(function.line == 41)
        #expect(function.coveredEdges == 7)
        #expect(function.totalEdges == 7)
        #expect(function.isCovered)
    }

    @Test("Zero covered edges means uncovered, whatever the prefix says")
    func parseUncovered() throws {
        let function = try #require(Coverage.parse(
            line: "UNCOVERED_FUNC: hits: 0 edges: 0/11 CBOR.subscript.getter CBOR+Accessors.swift:10"))
        #expect(!function.isCovered)
        #expect(function.totalEdges == 11)
    }

    @Test("A function name containing spaces survives")
    func parseNameWithSpaces() throws {
        let function = try #require(Coverage.parse(
            line: "COVERED_FUNC: hits: 1 edges: 1/1 outlined copy of CBOR /<compiler-generated>:0"))
        #expect(function.name == "outlined copy of CBOR")
        #expect(function.file == Coverage.compilerGenerated)
    }

    @Test("An absolute path is reduced to its file name, as some toolchains report one")
    func parseAbsolutePath() throws {
        let function = try #require(Coverage.parse(
            line: "COVERED_FUNC: hits: 1 edges: 1/1 f() /build/Sources/CBOR/CBORParser.swift:41"))
        #expect(function.file == "CBORParser.swift")
        #expect(function.line == 41)
    }

    @Test("Non-record lines are ignored, so the whole stream can be handed over",
          arguments: [
            "#2611\tDONE   cov: 521 ft: 2900 corp: 710/60Kb",
            "COVERAGE:",
            "==89843==WARNING: failed to spawn external symbolizer (errno: 9)",
            "",
            "COVERED_FUNC: malformed",
          ])
    func ignoresOtherLines(line: String) {
        #expect(Coverage.parse(line: line) == nil)
    }

    @Test("Parsing a full dump finds every record and nothing else")
    func parseSample() {
        #expect(Coverage.parse(Self.sample).count == 7)
    }

    // MARK: Filtering

    @Test("Compiler-generated, harness and line-0 entries are all excluded")
    func filtersNoise() {
        let files = Coverage.summarize(Coverage.parse(Self.sample)).files
        let names = Set(files.map(\.name))
        #expect(names == ["CBORParser.swift", "CBOR+Accessors.swift", "CBOREncoder.swift"])
        // The line-0 default argument generator is in CBOREncoder.swift, which
        // must therefore hold only the one real function.
        let encoder = try? #require(files.first { $0.name == "CBOREncoder.swift" })
        #expect(encoder?.functions.count == 1)
    }

    @Test("swift-fuzz's own sources never appear in a report about someone else's code")
    func excludesHarness() {
        let files = Coverage.summarize(Coverage.parse(Self.sample)).files
        #expect(!files.contains { Coverage.harnessFiles.contains($0.name) })
    }

    // MARK: Rolling up

    @Test("A file's edges are the sum of its functions'")
    func rollsUpEdges() throws {
        let files = Coverage.summarize(Coverage.parse(Self.sample)).files
        let parser = try #require(files.first { $0.name == "CBORParser.swift" })
        #expect(parser.coveredEdges == 10)   // 7 + 3
        #expect(parser.totalEdges == 16)     // 7 + 9
        #expect(parser.coveredFunctions == 2)
        #expect(parser.functions.count == 2)
    }

    @Test("Entered files come first, then the biggest gaps")
    func ordersEnteredFirst() {
        let files = Coverage.summarize(Coverage.parse(Self.sample)).files
        // CBORParser was entered, so it leads despite having the smallest gap.
        // The two never entered follow by size: 11 uncovered edges, then 7.
        #expect(files.map(\.name) == ["CBORParser.swift", "CBOR+Accessors.swift", "CBOREncoder.swift"])
    }

    @Test("A file with any coverage counts as entered")
    func entered() {
        func file(covered: Int) -> Coverage.File {
            Coverage.File(name: "F.swift", functions: [
                Coverage.Function(name: "f", file: "F.swift", line: 1,
                                  coveredEdges: covered, totalEdges: 10)
            ])
        }
        #expect(file(covered: 1).isEntered)
        #expect(!file(covered: 0).isEntered)
    }

    // MARK: The untouched tail

    /// 3 entered files and 25 the fuzzer never reached — Vapor's shape, where
    /// listing every untouched file is what made the report unreadable.
    static func lopsided() -> Coverage.Summary {
        var functions: [Coverage.Function] = []
        for index in 0..<3 {
            functions.append(Coverage.Function(
                name: "hit\(index)", file: "Hit\(index).swift", line: 1,
                coveredEdges: 5, totalEdges: 10))
        }
        for index in 0..<25 {
            functions.append(Coverage.Function(
                name: "miss\(index)", file: "Miss\(index).swift", line: 1,
                coveredEdges: 0, totalEdges: 100 + index))
        }
        return Coverage.summarize(functions)
    }

    @Test("Every entered file is listed, and the untouched tail is capped")
    func capsUntouched() {
        let report = Coverage.render(Self.lopsided(), target: "T", inputs: "1 corpus input")
        for index in 0..<3 {
            #expect(report.contains("Hit\(index).swift"))
        }
        // 25 untouched, 10 listed, 15 collapsed.
        #expect(report.contains("15 never-entered files not listed above"))
        #expect(report.contains("3 entered, 25 never entered"))
    }

    @Test("The largest untouched files survive the cut, being the ones worth a target")
    func capKeepsLargest() {
        let report = Coverage.render(Self.lopsided(), target: "T", inputs: "1 corpus input")
        // Miss24 has the most edges (124); Miss0 the fewest (100).
        #expect(report.contains("Miss24.swift"))
        #expect(!report.contains("Miss0.swift"))
    }

    @Test("The headline counts every file in scope, not just the listed ones")
    func headlineCountsUnlisted() {
        let report = Coverage.render(Self.lopsided(), target: "T", inputs: "1 corpus input")
        // 3 entered at 5/10, plus 25 untouched totalling 100...124 edges.
        let total = 3 * 10 + (0..<25).reduce(0) { $0 + 100 + $1 }
        #expect(report.contains("15/\(total) edges reached"))
    }

    @Test("Full detail lists every file and reports nothing as unlisted")
    func fullListsEverything() {
        let report = Coverage.render(
            Self.lopsided(), target: "T", inputs: "1 corpus input", full: true)
        #expect(report.contains("Miss0.swift"))
        #expect(!report.contains("not listed above"))
    }

    @Test("Uncovered functions are listed in source order")
    func gapsInSourceOrder() throws {
        let functions = [
            Coverage.Function(name: "b", file: "F.swift", line: 30, coveredEdges: 0, totalEdges: 1),
            Coverage.Function(name: "a", file: "F.swift", line: 10, coveredEdges: 0, totalEdges: 1),
            Coverage.Function(name: "hit", file: "F.swift", line: 20, coveredEdges: 1, totalEdges: 1),
        ]
        let file = Coverage.File(name: "F.swift", functions: functions)
        #expect(file.gaps.map(\.name) == ["a", "b"])
    }

    // MARK: Rendering

    @Test("The report names the target, the totals and every file")
    func rendersReport() {
        let files = Coverage.summarize(Coverage.parse(Self.sample)).files
        let report = Coverage.render(Coverage.Summary(files: files, dependencyFiles: 0, dependencyEdges: 0), target: "CBORDecode", inputs: "3 corpus inputs")
        #expect(report.contains("coverage for CBORDecode"))
        #expect(report.contains("3 corpus inputs"))
        #expect(report.contains("CBORParser.swift"))
        // 10 of 16 parser edges, and nothing anywhere else.
        #expect(report.contains("10/34 edges reached (29%) across 3 files"))
    }

    @Test("An empty report explains itself rather than printing an empty table")
    func rendersEmptyReport() {
        let report = Coverage.render(
            Coverage.Summary(files: [], dependencyFiles: 0, dependencyEdges: 0),
            target: "T", inputs: "0 corpus inputs")
        #expect(report.contains("No instrumented source files"))
    }

    @Test("The gap listing gives a file and line for each missed function")
    func rendersGaps() {
        let files = Coverage.summarize(Coverage.parse(Self.sample)).files
        let listing = Coverage.renderGaps(files)
        #expect(listing.contains("CBOREncoder.encode(_:)  CBOREncoder.swift:20"))
        #expect(listing.contains("CBOR.subscript.getter  CBOR+Accessors.swift:10"))
        // Covered functions are not gaps.
        #expect(!listing.contains("CBORParser.parse()"))
    }

    @Test("Fully covered code says so instead of printing an empty heading")
    func rendersNoGaps() {
        let file = Coverage.File(name: "F.swift", functions: [
            Coverage.Function(name: "f", file: "F.swift", line: 1, coveredEdges: 1, totalEdges: 1)
        ])
        #expect(Coverage.renderGaps([file]).contains("Every instrumented function was reached"))
    }

    @Test("Percentages round, and a zero denominator does not divide by zero")
    func percentages() {
        #expect(Coverage.percentage(1, of: 3) == "33%")
        #expect(Coverage.percentage(2, of: 3) == "67%")
        #expect(Coverage.percentage(0, of: 10) == "0%")
        #expect(Coverage.percentage(10, of: 10) == "100%")
        #expect(Coverage.percentage(0, of: 0) == "-")
    }

    // MARK: Demangling

    @Test("Swift's mangling prefixes are recognised",
          arguments: ["$s12BuggyLibraryAAO5parseyy", "_$s12BuggyLibraryAAO5parseyy"])
    func recognisesMangled(name: String) {
        #expect(Coverage.isMangled(name))
    }

    @Test("Names macOS already demangled are left alone",
          arguments: ["CBORParser.parse()", "outlined copy of CBOR", "", "main"])
    func ignoresReadable(name: String) {
        #expect(!Coverage.isMangled(name))
    }

    @Test("Demangled names replace mangled ones, and nothing else moves")
    func appliesDemangling() {
        let functions = [
            Coverage.Function(name: "$sABC", file: "F.swift", line: 1, coveredEdges: 0, totalEdges: 2),
            Coverage.Function(name: "readable()", file: "F.swift", line: 2, coveredEdges: 1, totalEdges: 1),
        ]
        let result = Coverage.applying(["$sABC": "A.b() -> ()"], to: functions)
        #expect(result.map(\.name) == ["A.b() -> ()", "readable()"])
        // Everything but the name is untouched.
        #expect(result[0].line == 1)
        #expect(result[0].totalEdges == 2)
    }

    @Test("An empty map is a no-op, which is how a missing demangler behaves")
    func appliesNothing() {
        let functions = [
            Coverage.Function(name: "$sABC", file: "F.swift", line: 1, coveredEdges: 0, totalEdges: 2)
        ]
        #expect(Coverage.applying([:], to: functions) == functions)
    }

    // MARK: Scope

    @Test("A scope keeps the package under test and counts what it withheld")
    func scopeFiltersDependencies() {
        let scope: Set<String> = ["CBORParser.swift"]
        let summary = Coverage.summarize(Coverage.parse(Self.sample), scope: scope)
        #expect(summary.files.map(\.name) == ["CBORParser.swift"])
        // CBOR+Accessors.swift (11 edges) and CBOREncoder.swift (7) are out.
        #expect(summary.dependencyFiles == 2)
        #expect(summary.dependencyEdges == 18)
    }

    @Test("No scope means everything is in scope, and nothing is reported withheld")
    func noScope() {
        let summary = Coverage.summarize(Coverage.parse(Self.sample), scope: nil)
        #expect(summary.files.count == 3)
        #expect(summary.dependencyFiles == 0)
    }

    @Test("Excluded files are never silently dropped from the report")
    func withheldIsReported() {
        let summary = Coverage.summarize(Coverage.parse(Self.sample), scope: ["CBORParser.swift"])
        let report = Coverage.render(summary, target: "T", inputs: "1 corpus input")
        #expect(report.contains("2 dependency files"))
        #expect(report.contains("--include-dependencies"))
    }

    @Test("A report scoped down to nothing explains itself")
    func everythingFilteredOut() {
        let summary = Coverage.summarize(Coverage.parse(Self.sample), scope: ["Nothing.swift"])
        let report = Coverage.render(summary, target: "T", inputs: "1 corpus input")
        #expect(report.contains("belongs to a dependency"))
        #expect(report.contains("--include-dependencies"))
    }

    // MARK: Diagnostics

    @Test("Both symbolizer failure modes are recognised", arguments: [
        "==1==WARNING: failed to spawn external symbolizer (errno: 9)",
        "==1==WARNING: invalid path to external symbolizer!",
        "==1==WARNING: Failed to use and restart external symbolizer!",
    ])
    func recognisesSymbolizerFailures(line: String) {
        #expect(Coverage.symbolizerFailed(in: line))
    }

    @Test("A clean run is not mistaken for a symbolizer failure")
    func noFalseSymbolizerFailure() {
        #expect(!Coverage.symbolizerFailed(in: Self.sample))
    }

    @Test("A blocked spawn is distinguished from a missing binary")
    func distinguishesBlockedFromMissing() {
        let blocked = "==1==WARNING: failed to spawn external symbolizer (errno: 9)"
        let missing = "==1==WARNING: invalid path to external symbolizer!"
        #expect(blocked.contains(Coverage.symbolizerBlocked))
        #expect(!missing.contains(Coverage.symbolizerBlocked))
    }

    // libFuzzer prints a COVERAGE block even when it dies on a crashing input,
    // and every function in it comes back uncovered. Rendering that produced a
    // confident "0/44680 edges reached (0%)" for a target whose corpus held one
    // crashing input — a wrong finding rather than a visible failure.
    @Test("A run that died is reported as a failure, not as zero coverage")
    func crashedRunMessage() {
        let message = Coverage.crashedMessage(target: "URIComponents", status: 77)
        #expect(message.contains("exit 77"))
        #expect(message.contains("Corpus/URIComponents"))
        // Points at the verb that identifies which input it is.
        #expect(message.contains("--replay"))
        // Must not read as a coverage figure.
        #expect(!message.contains("edges reached"))
    }

    @Test("The missing-symbolizer message names the variable that fixes it")
    func missingSymbolizerMessage() {
        let message = Coverage.missingSymbolizerMessage(target: "MyTarget")
        #expect(message.contains("ASAN_SYMBOLIZER_PATH"))
        #expect(message.contains("llvm-symbolizer"))
    }


    @Test("The sandbox message names the flag that fixes it")
    func sandboxMessage() {
        let message = Coverage.sandboxMessage(target: "MyTarget")
        #expect(message.contains("--disable-sandbox"))
        #expect(message.contains("fuzz MyTarget --coverage"))
    }
}
