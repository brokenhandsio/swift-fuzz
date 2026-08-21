import Foundation
import Testing

// `FuzzEnvironment.swift` here is a symlink to the command plugin's copy — see
// the note in ArgumentsTests.swift for why.

@Suite("Fuzz environment")
struct FuzzEnvironmentTests {
    @Test("The selected target is passed to the binary")
    func setsTarget() {
        let environment = FuzzEnvironment.make(target: "MyTarget", symbolizer: nil, base: [:])
        #expect(environment["FUZZ_TARGET"] == "MyTarget")
        #expect(environment["FUZZ_LIST_TARGETS"] == nil)
    }

    @Test("Listing targets does not also select one")
    func listing() {
        let environment = FuzzEnvironment.make(
            target: nil, symbolizer: nil, listTargets: true, base: [:])
        #expect(environment["FUZZ_LIST_TARGETS"] == "1")
        #expect(environment["FUZZ_TARGET"] == nil)
    }

    @Test("The toolchain's symbolizer is passed through, so PATH does not have to hold one")
    func setsSymbolizer() {
        let environment = FuzzEnvironment.make(
            target: "T", symbolizer: URL(fileURLWithPath: "/toolchain/llvm-symbolizer"), base: [:])
        #expect(environment["ASAN_SYMBOLIZER_PATH"] == "/toolchain/llvm-symbolizer")
    }

    @Test("An existing ASAN_SYMBOLIZER_PATH wins; someone who set it meant it")
    func doesNotOverride() {
        let environment = FuzzEnvironment.make(
            target: "T",
            symbolizer: URL(fileURLWithPath: "/toolchain/llvm-symbolizer"),
            base: ["ASAN_SYMBOLIZER_PATH": "/mine/llvm-symbolizer"])
        #expect(environment["ASAN_SYMBOLIZER_PATH"] == "/mine/llvm-symbolizer")
    }

    @Test("No symbolizer to offer leaves the variable unset rather than empty")
    func noSymbolizer() {
        let environment = FuzzEnvironment.make(target: "T", symbolizer: nil, base: [:])
        #expect(environment["ASAN_SYMBOLIZER_PATH"] == nil)
    }

    // The whole point of the check is to fail before a long run, so a path that
    // is merely *set* must not count as a path that works.
    @Test("A symbolizer that is not there does not count as available")
    func detectsUnusableSymbolizer() {
        #expect(!FuzzEnvironment.hasSymbolizer([:]))
        #expect(!FuzzEnvironment.hasSymbolizer(["ASAN_SYMBOLIZER_PATH": "/nope/llvm-symbolizer"]))
    }

    @Test("A real executable does count")
    func detectsUsableSymbolizer() {
        #expect(FuzzEnvironment.hasSymbolizer(["ASAN_SYMBOLIZER_PATH": "/bin/sh"]))
    }
}
