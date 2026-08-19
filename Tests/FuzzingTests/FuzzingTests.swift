import Foundation
import Testing
@testable import Fuzzing

@Suite("FuzzTarget registration")
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
            seen.value = Array(bytes)
        }
        let input: [UInt8] = [0xA1, 0x01, 0x02]
        input.withUnsafeBytes { target.body($0) }
        #expect(seen.value == input)
    }

    @Test("A zero-length input is delivered as an empty buffer, not a crash")
    func emptyInput() {
        let count = Box(-1)
        let target = FuzzTarget("empty-probe") { bytes in
            count.value = bytes.count
        }
        let empty: [UInt8] = []
        empty.withUnsafeBytes { target.body($0) }
        #expect(count.value == 0)
    }
}

@Suite("Generated entry point")
struct GeneratedSourceTests {
    // The generated file is the contract between the C shim and Swift: the shim
    // calls these two symbols by name. If they drift, the link fails with an
    // undefined symbol and no hint as to why. Plugin targets cannot be imported,
    // so the template is read from source.
    static let template: String = {
        let plugin = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // FuzzingTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
            .appending(path: "Plugins/FuzzTargetPlugin/FuzzTargetPlugin.swift")
        return (try? String(contentsOf: plugin, encoding: .utf8)) ?? ""
    }()

    @Test("Generated source declares the symbols the C shim calls")
    func declaresShimSymbols() {
        #expect(Self.template.contains(#"@_cdecl("swift_fuzz_initialize")"#))
        #expect(Self.template.contains(#"@_cdecl("swift_fuzz_run")"#))
    }

    @Test("Generated source touches fuzzTargets so the lazy global initialises")
    func touchesFuzzTargets() {
        #expect(Self.template.contains("fuzzTargets()"))
    }

    @Test("Generated source calls FuzzRunner.initialize before any input runs")
    func callsInitialize() {
        #expect(Self.template.contains("FuzzRunner.initialize()"))
    }
}

/// The fuzz body is `@Sendable`, so tests observe it through a reference rather
/// than by capturing a `var`. Single-threaded in these tests.
private final class Box<Value>: @unchecked Sendable {
    var value: Value
    init(_ value: Value) { self.value = value }
}
