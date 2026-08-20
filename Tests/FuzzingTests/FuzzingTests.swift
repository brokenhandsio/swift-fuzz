import Foundation
import Testing
@testable import Fuzzing

// Serialized because these mutate `FuzzRunner`'s process-global registry, which
// is deliberately unsynchronised: libFuzzer registers once, on one thread,
// before any input is dispatched, so a lock on that path would buy nothing in
// production. Tests run in parallel by default and would otherwise race — which
// showed up as an intermittent failure on Linux, passing on a re-run.
@Suite("FuzzTarget registration", .serialized)
struct FuzzTargetTests {
    // The registry is process-global by design (libFuzzer registers once at
    // startup), so this asserts on membership rather than on a count, which
    // other tests in this run would perturb.
    @Test("Creating a target registers it under its name")
    func registersOnInit() {
        #expect(!FuzzRunner.registeredNames.contains("registration-probe"))
        FuzzTarget("registration-probe") { _ in }
        #expect(FuzzRunner.registeredNames.contains("registration-probe"))
    }

    @Test("The body receives exactly the bytes it was given")
    func bodyReceivesBytes() {
        let seen = Box<[UInt8]>([])
        let target = FuzzTarget("byte-probe") { bytes in
            // Span is not a Sequence, so a copy is an explicit index loop.
            var copy: [UInt8] = []
            for index in 0..<bytes.count { copy.append(bytes[index]) }
            seen.value = copy
        }
        let input: [UInt8] = [0xA1, 0x01, 0x02]
        unsafe input.withUnsafeBytes { unsafe target.body($0) }
        #expect(seen.value == input)
    }

    @Test("A structured target registers like any other")
    func structuredRegisters() {
        FuzzTarget.structured("structured-probe") { _ in }
        #expect(FuzzRunner.registeredNames.contains("structured-probe"))
    }

    @Test("A structured body sees the input through a provider")
    func structuredReceivesInput() {
        let seen = Box<[UInt8]>([])
        let target = FuzzTarget.structured("structured-bytes") { data in
            seen.value = data.remainingBytes()
        }
        let input: [UInt8] = [4, 5, 6]
        unsafe input.withUnsafeBytes { unsafe target.body($0) }
        #expect(seen.value == input)
    }

    // Only registration is asserted here. Invoking an asynchronous body means
    // blocking the calling thread while a task runs, and swift-testing runs
    // tests on the cooperative pool — blocking a pool thread from a test is
    // exactly the deadlock the API documents. The example package and CI
    // exercise the bridge for real, under libFuzzer, where the calling thread
    // belongs to libFuzzer rather than to the pool.
    @Test("An async target registers like any other")
    func asyncRegisters() {
        FuzzTarget.async("async-probe") { _ in }
        FuzzTarget.structuredAsync("structured-async-probe") { _ in }
        #expect(FuzzRunner.registeredNames.contains("async-probe"))
        #expect(FuzzRunner.registeredNames.contains("structured-async-probe"))
    }

    @Test("A zero-length input is delivered as an empty buffer, not a crash")
    func emptyInput() {
        let count = Box(-1)
        let target = FuzzTarget("empty-probe") { bytes in
            count.value = bytes.count
        }
        let empty: [UInt8] = []
        unsafe empty.withUnsafeBytes { unsafe target.body($0) }
        #expect(count.value == 0)
    }
}

@Suite("Generated entry points")
struct GeneratedSourceTests {
    // The generated file is a linking contract, and a broken one fails with an
    // undefined symbol and no hint as to why. Plugin targets cannot be imported,
    // so the templates are read from source.
    static let plugin: String = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // FuzzingTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
            .appending(path: "Plugins/FuzzTargetPlugin/FuzzTargetPlugin.swift")
        return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }()

    /// The C shim in Examples/, which the paired template has to match.
    static let shim: String = {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "Examples/BuggyLibrary/Fuzzing/FuzzTargets/BuggyParseShim/shim.c")
        return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }()

    @Test("Paired template declares exactly the symbols shim.c calls")
    func pairedMatchesShim() {
        // Both halves of the contract, checked against each other rather than
        // against a hardcoded list, so drift on either side fails the test.
        for symbol in ["swift_fuzz_initialize", "swift_fuzz_run"] {
            #expect(Self.plugin.contains(#"@_cdecl("\#(symbol)")"#), "template missing \(symbol)")
            #expect(Self.shim.contains(symbol), "shim.c missing \(symbol)")
        }
    }

    @Test("Standalone template declares libFuzzer's own entry points")
    func standaloneDeclaresLibFuzzerSymbols() {
        #expect(Self.plugin.contains(#"@_cdecl("LLVMFuzzerInitialize")"#))
        #expect(Self.plugin.contains(#"@_cdecl("LLVMFuzzerTestOneInput")"#))
    }

    @Test("The C shim does not define main, so libFuzzer's runtime supplies it")
    func shimHasNoMain() {
        #expect(!Self.shim.contains("int main("))
    }

    @Test("Both templates touch fuzzTargets and initialise the runner")
    func bothTemplatesWireUpTheRegistry() {
        // Two of each: one occurrence per template.
        #expect(Self.plugin.components(separatedBy: "fuzzTargets()").count - 1 == 2)
        #expect(Self.plugin.components(separatedBy: "FuzzRunner.initialize()").count - 1 == 2)
        #expect(Self.plugin.components(separatedBy: "FuzzRunner.run(data, size)").count - 1 == 2)
    }
}

/// The fuzz body is `@Sendable`, so tests observe it through a reference rather
/// than by capturing a `var`. Single-threaded in these tests.
private final class Box<Value>: @unchecked Sendable {
    var value: Value
    init(_ value: Value) { self.value = value }
}
