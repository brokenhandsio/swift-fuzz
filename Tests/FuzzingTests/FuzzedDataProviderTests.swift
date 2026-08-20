import Testing
@testable import Fuzzing

/// Runs `body` with a provider over `bytes`.
private func withProvider<T>(_ bytes: [UInt8], _ body: (inout FuzzedDataProvider) -> T) -> T {
    unsafe bytes.withUnsafeBytes { raw in
        var provider = unsafe FuzzedDataProvider(raw)
        return body(&provider)
    }
}

@Suite("FuzzedDataProvider")
struct FuzzedDataProviderTests {
    @Test("Bytes come from the front, control values from the back")
    func opposingEnds() {
        // The split is what keeps a payload at a stable offset while the fuzzer
        // mutates it, so it is worth pinning rather than leaving to chance.
        let (front, back) = withProvider([1, 2, 3, 4, 0xAA]) { data in
            (data.bytes(2), data.integer(UInt8.self))
        }
        #expect(front == [1, 2])
        #expect(back == 0xAA)
    }

    @Test("Consuming from both ends never overlaps")
    func endsDoNotOverlap() {
        let (bytes, value, remaining) = withProvider([1, 2, 3]) { data in
            let v = data.integer(UInt8.self)   // takes 3 from the back
            return (data.bytes(10), v, data.remainingCount)
        }
        #expect(value == 3)
        #expect(bytes == [1, 2])
        #expect(remaining == 0)
    }

    @Test("An exhausted provider yields zeros rather than failing")
    func exhaustion() {
        // A fuzzer spends most of its time on tiny inputs; if this trapped or
        // returned nil the harness would spend most of its time in error paths.
        let (int, flag, bytes) = withProvider([]) { data in
            (data.integer(UInt32.self), data.bool(), data.bytes(8))
        }
        #expect(int == 0)
        #expect(flag == false)
        #expect(bytes.isEmpty)
    }

    @Test("Byte requests are truncated, not rejected")
    func truncates() {
        let bytes = withProvider([1, 2]) { $0.bytes(100) }
        #expect(bytes == [1, 2])
    }

    @Test("Integers stay inside the requested range", arguments: [
        [] as [UInt8], [0], [255], [7, 200, 13], [0xFF, 0xFF, 0xFF, 0xFF],
    ])
    func rangesHold(input: [UInt8]) {
        let value = withProvider(input) { $0.integer(in: 10...20) }
        #expect((10...20).contains(value))
    }

    @Test("A single-value range needs no input")
    func degenerateRange() {
        let (value, remaining) = withProvider([]) { ($0.integer(in: 5...5), $0.remainingCount) }
        #expect(value == 5)
        #expect(remaining == 0)
    }

    @Test("A full-width range is supported")
    func fullWidthRange() {
        // `span + 1` overflows here, so this takes a separate path.
        let value = withProvider([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) {
            $0.integer(in: UInt64.min...UInt64.max)
        }
        #expect(value == UInt64.max)
    }

    @Test("The same bytes always produce the same values")
    func deterministic() {
        // Saved crashing inputs are worthless if this does not hold.
        func run() -> (UInt32, Bool, [UInt8]) {
            withProvider([9, 8, 7, 6, 5, 4, 3, 2, 1]) { data in
                (data.integer(in: 0...1000), data.bool(), data.bytes(3))
            }
        }
        #expect(run() == run())
    }

    @Test("Picking from a collection stays in bounds")
    func picksElements() {
        let choices = ["a", "b", "c"]
        for seed in 0...255 {
            let picked = withProvider([UInt8(seed)]) { $0.element(of: choices) }
            #expect(picked.map(choices.contains) ?? false)
        }
    }

    @Test("Picking from an empty collection yields nil")
    func picksNothing() {
        #expect(withProvider([1, 2, 3]) { $0.element(of: [Int]()) } == nil)
    }

    @Test("Enum cases are chosen from allCases")
    func picksEnumCases() {
        enum Choice: CaseIterable, Equatable { case first, second, third }
        for seed in 0...20 {
            let picked = withProvider([UInt8(seed)]) { $0.caseOf(Choice.self) }
            #expect(picked != nil)
        }
    }

    @Test("remainingCount tracks both ends")
    func tracksRemaining() {
        withProvider([1, 2, 3, 4, 5, 6]) { data in
            #expect(data.remainingCount == 6)
            _ = data.bytes(2)
            #expect(data.remainingCount == 4)
            _ = data.integer(UInt8.self)
            #expect(data.remainingCount == 3)
            _ = data.remainingBytes()
            #expect(data.isEmpty)
        }
    }
}

@Suite("Fuzzable")
struct FuzzableTests {
    @Test("Integers round-trip through the provider")
    func scalars() {
        // Consumed from the back, most significant byte first — so 42 has to be
        // the *last* byte read, which is the first in the array.
        let value = withProvider([42, 0, 0, 0, 0, 0, 0, 0]) { $0.value(UInt64.self) }
        #expect(value == 42)
    }

    @Test("A short input yields a small value, not a huge one")
    func shortInputStaysSmall() {
        // Consuming a full width and padding the low bits would make this
        // 42 << 56, which would send every harness straight into its
        // out-of-range paths.
        #expect(withProvider([42]) { $0.value(UInt64.self) } == 42)
    }

    @Test("Doubles are built from bit patterns, so NaN and infinity occur")
    func floatsCoverSpecialValues() {
        let nan = withProvider([0xFF, 0xF8, 0, 0, 0, 0, 0, 0].reversed()) { $0.value(Double.self) }
        #expect(nan.isNaN || nan.isInfinite || nan.isFinite) // total, whatever the bits
    }

    @Test("Array length is bounded so one byte cannot request a huge allocation")
    func arraysAreBounded() {
        // Without a bound the fuzzer finds the allocation before it finds a bug.
        let values = withProvider([UInt8](repeating: 0xFF, count: 600)) { $0.value([UInt8].self) }
        #expect(values.count <= 255)
    }

    @Test("Optionals consume a flag then the value")
    func optionals() {
        // The flag is read from the back, so it is the last byte that decides.
        let results = (0...20).map { seed in
            withProvider([1, 2, 3, 4, 5, 6, 7, UInt8(seed)]) { $0.value(UInt8?.self) }
        }
        #expect(results.contains { $0 != nil })
        #expect(results.contains { $0 == nil })
    }

    @Test("Strings are repaired rather than rejected on invalid UTF-8")
    func stringsAreTotal() {
        let text = withProvider([0xFF, 0xFE, 0x41]) { $0.value(String.self) }
        #expect(text.contains("A"))
    }

    @Test("A custom Fuzzable composes from the provider")
    func customType() {
        struct Request: Fuzzable, Equatable {
            var retries: UInt8
            var verbose: Bool
            init(from provider: inout FuzzedDataProvider) {
                retries = provider.integer(in: 0...3)
                verbose = provider.bool()
            }
        }
        let request = withProvider([1, 2, 3, 4]) { $0.value(Request.self) }
        #expect((0...3).contains(request.retries))
    }
}

@Suite("Owned input")
struct OwnedProviderTests {
    // The asynchronous targets own their bytes, because the input has to
    // outlive the synchronous call libFuzzer makes. Same behaviour either way.
    @Test("An array-backed provider behaves like a buffer-backed one")
    func matchesBorrowed() {
        let input: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]

        var owned = FuzzedDataProvider(input)
        let ownedResult = (owned.integer(in: UInt16(0)...UInt16(1000)), owned.bool(), owned.bytes(3))

        let borrowedResult = unsafe input.withUnsafeBytes { raw -> (UInt16, Bool, [UInt8]) in
            var borrowed = unsafe FuzzedDataProvider(raw)
            return (borrowed.integer(in: UInt16(0)...UInt16(1000)), borrowed.bool(), borrowed.bytes(3))
        }

        #expect(ownedResult.0 == borrowedResult.0)
        #expect(ownedResult.1 == borrowedResult.1)
        #expect(ownedResult.2 == borrowedResult.2)
    }

    @Test("An empty array-backed provider is exhausted, not crashing")
    func emptyOwned() {
        var provider = FuzzedDataProvider([])
        #expect(provider.isEmpty)
        #expect(provider.integer(UInt32.self) == 0)
        #expect(provider.bytes(4).isEmpty)
    }
}
