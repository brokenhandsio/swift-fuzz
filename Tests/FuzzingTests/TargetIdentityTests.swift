import Testing
@_spi(Generated) @testable import Fuzzing

@Suite("Target identity")
struct TargetIdentityTests {
    @Test("Native executable names select logical targets, with explicit overrides")
    func exportedSelection() {
        let names = ["First", "Second"]
        #expect(FuzzRunner.targetSelector(explicit: nil, executable: "/out/Second", names: names) == "Second")
        #expect(FuzzRunner.targetSelector(explicit: "First", executable: "/out/Second", names: names) == "First")
        #expect(FuzzRunner.targetSelector(explicit: nil, executable: "/out/Unknown", names: names) == nil)
    }
    @Test("Portable logical names are accepted", arguments: ["A", "_private", "URL-Parser_2", String(repeating: "a", count: 128)])
    func valid(_ name: String) {
        #expect(TargetIdentity.validationError([name]) == nil)
    }

    @Test("Names cannot escape directories or corrupt discovery", arguments: [
        "", ".", "..", "../escape", "a/b", "a\\b", "a\nb", "a\rb", " a", "a ", "-flag", "9leading",
        "a.b", "a\0b", "é", "llvm-symbolizer", "LLVM-Symbolizer-Swift", String(repeating: "a", count: 129),
    ])
    func invalid(_ name: String) {
        #expect(TargetIdentity.validationError([name]) != nil)
    }

    @Test("Collisions include case-insensitive filesystems", arguments: [["A", "A"], ["Parser", "parser"]])
    func duplicates(_ names: [String]) {
        #expect(TargetIdentity.validationError(names)?.contains("Duplicate") == true)
    }
}
