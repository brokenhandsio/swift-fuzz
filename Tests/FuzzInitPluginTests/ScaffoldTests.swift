import Foundation
import Testing

// `Scaffold.swift` here is a symlink to the plugin's copy, not a duplicate —
// see Tests/FuzzCommandPluginTests for why.

@Suite("Scaffolded files")
struct ScaffoldTests {
    /// The paired template the build-tool plugin generates. The scaffolded C
    /// shim has to agree with it, symbol for symbol.
    static let generatedPairedTemplate: String = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Plugins/FuzzTargetPlugin/FuzzTargetPlugin.swift")
        return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }()

    @Test("The scaffolded shim calls exactly the symbols the build-tool plugin generates")
    func shimMatchesGeneratedTemplate() {
        // This is the link contract. If fuzz-init and FuzzTargetPlugin disagree
        // on a name, the scaffolded target fails to link with an undefined
        // symbol and nothing points at the cause.
        for symbol in ["swift_fuzz_run", "swift_fuzz_initialize"] {
            #expect(Scaffold.shim.contains(symbol), "shim template missing \(symbol)")
            #expect(Self.generatedPairedTemplate.contains(#"@_cdecl("\#(symbol)")"#),
                    "build-tool plugin no longer generates \(symbol)")
        }
    }

    @Test("The scaffolded shim supplies libFuzzer's entry points but not main")
    func shimHasEntryPointsButNoMain() {
        #expect(Scaffold.shim.contains("LLVMFuzzerTestOneInput"))
        #expect(Scaffold.shim.contains("LLVMFuzzerInitialize"))
        // libFuzzer's runtime provides main; defining one here is the collision
        // the C shim exists to avoid.
        #expect(!Scaffold.shim.contains("int main("))
    }

    @Test("The harness stub names the target and declares fuzzTargets")
    func harnessStub() {
        let harness = Scaffold.harness(target: "JSONParsing")
        #expect(harness.contains(#"FuzzTarget("JSONParsing")"#))
        #expect(harness.contains("let fuzzTargets: @Sendable () -> Void"))
        #expect(harness.contains("import Fuzzing"))
    }

    @Test("The paired stanza declares both targets and points the executable at the shim")
    func pairedStanza() {
        let stanza = Scaffold.manifestStanza(target: "Foo", standalone: false)
        #expect(stanza.contains(#"name: "Foo""#))
        #expect(stanza.contains(#"name: "FooTarget""#))
        #expect(stanza.contains(#"path: "FuzzTargets/FooShim""#))
        #expect(stanza.contains("FuzzTargetPlugin"))
    }

    @Test("The standalone stanza declares one target and no shim")
    func standaloneStanza() {
        let stanza = Scaffold.manifestStanza(target: "Foo", standalone: true)
        #expect(stanza.contains(#"name: "Foo""#))
        #expect(!stanza.contains("Shim"))
        #expect(!stanza.contains(#"name: "FooTarget""#))
        #expect(stanza.contains("FuzzTargetPlugin"))
    }

    @Test("Only names usable as a SwiftPM target are accepted", arguments: [
        "JSONParsing", "CBORDecode", "Fuzz_1", "_private",
    ])
    func acceptsValidNames(name: String) throws {
        try Scaffold.validate(name: name)
    }

    @Test("Names that would break the manifest or the filesystem are rejected", arguments: [
        "", "9leading", "has-hyphen", "has space", "dot.dot", "../escape", "sla/sh",
    ])
    func rejectsInvalidNames(name: String) {
        #expect(throws: FuzzInitError.self) {
            try Scaffold.validate(name: name)
        }
    }
}
