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
        let files = Coverage.summarize(Coverage.parse(Self.sample))
        let names = Set(files.map(\.name))
        #expect(names == ["CBORParser.swift", "CBOR+Accessors.swift", "CBOREncoder.swift"])
        // The line-0 default argument generator is in CBOREncoder.swift, which
        // must therefore hold only the one real function.
        let encoder = try? #require(files.first { $0.name == "CBOREncoder.swift" })
        #expect(encoder?.functions.count == 1)
    }

    @Test("swift-fuzz's own sources never appear in a report about someone else's code")
    func excludesHarness() {
        let files = Coverage.summarize(Coverage.parse(Self.sample))
        #expect(!files.contains { Coverage.harnessFiles.contains($0.name) })
    }

    // MARK: Rolling up

    @Test("A file's edges are the sum of its functions'")
    func rollsUpEdges() throws {
        let files = Coverage.summarize(Coverage.parse(Self.sample))
        let parser = try #require(files.first { $0.name == "CBORParser.swift" })
        #expect(parser.coveredEdges == 10)   // 7 + 3
        #expect(parser.totalEdges == 16)     // 7 + 9
        #expect(parser.coveredFunctions == 2)
        #expect(parser.functions.count == 2)
    }

    @Test("Files are ordered by what is missing, so the biggest gap reads first")
    func ordersByGap() {
        let files = Coverage.summarize(Coverage.parse(Self.sample))
        // 11 uncovered edges, then 7, then 6.
        #expect(files.map(\.name) == ["CBOR+Accessors.swift", "CBOREncoder.swift", "CBORParser.swift"])
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
        let files = Coverage.summarize(Coverage.parse(Self.sample))
        let report = Coverage.render(files, target: "CBORDecode", inputs: "3 corpus inputs")
        #expect(report.contains("coverage for CBORDecode"))
        #expect(report.contains("3 corpus inputs"))
        #expect(report.contains("CBORParser.swift"))
        // 10 of 16 parser edges, and nothing anywhere else.
        #expect(report.contains("10/34 edges reached (29%) across 3 files"))
    }

    @Test("An empty report explains itself rather than printing an empty table")
    func rendersEmptyReport() {
        let report = Coverage.render([], target: "T", inputs: "0 corpus inputs")
        #expect(report.contains("No instrumented source files"))
    }

    @Test("The gap listing gives a file and line for each missed function")
    func rendersGaps() {
        let files = Coverage.summarize(Coverage.parse(Self.sample))
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

    // MARK: Diagnostics

    @Test("The sandbox message names the flag that fixes it")
    func sandboxMessage() {
        let message = Coverage.sandboxMessage(target: "MyTarget")
        #expect(message.contains("--disable-sandbox"))
        #expect(message.contains("fuzz MyTarget --coverage"))
    }
}
