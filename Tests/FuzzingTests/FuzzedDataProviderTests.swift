import Testing
// SPI import: FuzzRunner's entry points are not public API.
@_spi(Generated) @testable import Fuzzing

/// Runs `body` with a provider over `bytes`.
private func withProvider<T>(_ bytes: [UInt8], _ body: (inout FuzzedDataProvider) -> T) -> T {
    var provider = FuzzedDataProvider(bytes)
    return body(&provider)
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

/// Builds an input whose first ``FuzzedDataProvider/chunk()`` is exactly
/// `payload`, by searching for control bytes that draw that length.
///
/// The tests below used to hand-write a single length byte at the back. That
/// encoded the drawing scheme into every assertion, so changing the scheme
/// broke eight tests that were not about the scheme at all. Searching for the
/// bytes keeps each test about the property it names.
private func inputYielding(chunk payload: [UInt8], followedBy rest: [UInt8] = []) -> [UInt8] {
    for high in UInt8.min...UInt8.max {
        for low in UInt8.min...UInt8.max {
            let input = payload + rest + [high, low]
            if withProvider(input, { $0.chunk() }) == payload { return input }
        }
    }
    Issue.record("no input draws a chunk of \(payload.count) bytes")
    return payload
}

@Suite("Length-prefixed values")
struct ChunkTests {
    @Test("A chunk takes its bytes from the front")
    func chunkTakesFromFront() {
        let input: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let chunk = withProvider(input) { $0.chunk() }
        #expect(chunk == Array(input.prefix(chunk.count)))
    }

    @Test("A chunk takes its length from the back, not the front")
    func lengthComesFromTheBack() {
        // Varying the back changes how much is taken...
        let varyingBack = Set((0..<32).map { back in
            withProvider([1, 2, 3, 4, 5, 6, 7, 8, UInt8(back)]) { $0.chunk() }.count
        })
        #expect(varyingBack.count > 1)

        // ...while varying the front does not. That separation is what keeps a
        // payload mutation from shifting every control value.
        let varyingFront = Set((0..<32).map { front in
            withProvider([UInt8(front), 2, 3, 4, 5, 6, 7, 8, 0x05]) { $0.chunk() }.count
        })
        #expect(varyingFront.count == 1)
    }

    @Test("A chunk is truncated rather than failing when the input is short")
    func chunkTruncates() {
        let chunk = withProvider([1, 2, 0xFF]) { $0.chunk() }
        #expect(chunk.count <= 3)
    }

    @Test("An exhausted provider yields an empty chunk")
    func chunkOnEmpty() {
        #expect(withProvider([]) { $0.chunk() }.isEmpty)
    }

    // The bug this suite exists to prevent. A length drawn from a fixed 0...255
    // exceeds what is left on almost every realistic input, so the first chunk
    // took everything: a harness pulling three header values out of 46 bytes
    // got 45, then nothing, then nothing, and silently fuzzed one field.
    @Test("A chunk leaves data behind for the draws that follow")
    func chunkDoesNotStarve() {
        // Enumerated rather than sampled, so this cannot flake.
        var leftSomething = 0
        for back in UInt8.min...UInt8.max {
            let input = Array(repeating: UInt8(0x41), count: 40) + [back]
            let second = withProvider(input) { data in
                _ = data.chunk()
                return data.chunk()
            }
            if !second.isEmpty { leftSomething += 1 }
        }
        // The old fixed 0...255 bound took everything whenever the drawn length
        // reached what was left, which for a 40-byte input is 216 of the 256
        // possible draws. Drawing against what remains inverts that. It is not
        // 256/256, and should not be: a draw that legitimately lands at the top
        // still takes the lot.
        #expect(leftSomething > 150, "only \(leftSomething)/256 inputs left data for a second chunk")
    }

    @Test("Several chunks come out in order without overlapping")
    func severalChunks() {
        let input: [UInt8] = Array(repeating: 0, count: 8).enumerated().map { UInt8($0.offset) }
        let (first, second) = withProvider(input + [0x40, 0x21]) { data in
            (data.chunk(), data.chunk())
        }
        // Consecutive slices of the front, in order, never overlapping.
        #expect(first == Array(input.prefix(first.count)))
        #expect(second == Array(input.dropFirst(first.count).prefix(second.count)))
    }

    @Test("Text repairs invalid UTF-8 rather than failing")
    func textIsTotal() {
        let input = inputYielding(chunk: [0xFF, 0x41])
        let text = withProvider(input) { $0.text() }
        #expect(text.contains("A"))
    }

    @Test("optionalText distinguishes absent from empty")
    func optionalTextSeparatesAbsentFromEmpty() {
        // An API where "no scheme" and "empty scheme" differ needs this.
        #expect(withProvider(inputYielding(chunk: [])) { $0.optionalText() } == nil)
        #expect(withProvider(inputYielding(chunk: [0x41])) { $0.optionalText() } == "A")
    }

    @Test("remainingText takes everything the chunk left")
    func remainingText() {
        let input = inputYielding(chunk: [0x41], followedBy: [0x42, 0x43])
        let (first, rest) = withProvider(input) { data in
            (data.chunk(), data.remainingText())
        }
        #expect(first == [0x41])
        #expect(rest == "BC")
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
        let input = inputYielding(chunk: [0xFF, 0xFE, 0x41])
        let text = withProvider(input) { $0.value(String.self) }
        #expect(text.contains("A"))
    }

    // A greedy String consumed the whole input, so every field declared after
    // one got zeros forever and `[String]` was one element and then empties.
    @Test("A String leaves data for the fields declared after it")
    func stringComposes() {
        struct Pair: Fuzzable {
            var text: String
            var number: Int
            init(from provider: inout FuzzedDataProvider) {
                text = provider.value()
                number = provider.value()
            }
        }
        var nonZero = 0
        for back in UInt8.min...UInt8.max {
            let input = Array("hello world, plenty of bytes here".utf8) + [back]
            if withProvider(input, { $0.value(Pair.self) }).number != 0 { nonZero += 1 }
        }
        #expect(nonZero > 200, "only \(nonZero)/256 inputs left anything for the second field")
    }

    @Test("An array of strings spreads the input across its elements")
    func arrayOfStringsComposes() {
        var populated = 0
        for back in UInt8.min...UInt8.max {
            let input = Array("abcdefghijklmnopqrstuvwxyz".utf8) + [back]
            let items = withProvider(input) { $0.value([String].self) }
            if items.count(where: { !$0.isEmpty }) > 1 { populated += 1 }
        }
        #expect(populated > 128, "only \(populated)/256 inputs populated more than one element")
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
    @Test("Changing the caller's array preserves the provider's input")
    func ownsInput() {
        var input: [UInt8] = [1, 2, 3]
        var provider = FuzzedDataProvider(input)
        input[1] = 99
        #expect(provider.remainingBytes() == [1, 2, 3])
        #expect(input == [1, 99, 3])
    }

    @Test("Copies preserve the cursor and consume independently")
    func independentCopies() {
        var original = FuzzedDataProvider([1, 2, 3, 4, 5])
        #expect(original.bytes(1) == [1])
        #expect(original.integer(UInt8.self) == 5)
        var copy = original
        #expect(copy.integer(UInt8.self) == 4)
        #expect(original.bytes(1) == [2])
        #expect(copy.remainingBytes() == [2, 3])
        #expect(original.remainingBytes() == [3, 4])
    }

    @Test("A provider can cross a task boundary with its current cursor")
    func sendableInput() async {
        var provider = FuzzedDataProvider([1, 2, 3])
        _ = provider.bytes(1)
        let snapshot = provider
        let task = Task.detached { @Sendable in
            var copy = snapshot
            return copy.remainingBytes()
        }
        #expect(await task.value == [2, 3])
        #expect(provider.remainingBytes() == [2, 3])
    }

    @Test("An empty array-backed provider is exhausted, not crashing")
    func emptyOwned() {
        var provider = FuzzedDataProvider([])
        #expect(provider.isEmpty)
        #expect(provider.integer(UInt32.self) == 0)
        #expect(provider.bytes(4).isEmpty)
    }
}
