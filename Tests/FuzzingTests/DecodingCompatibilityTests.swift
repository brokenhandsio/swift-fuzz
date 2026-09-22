import Testing
import Fuzzing

// These are deliberately literal fixtures, rather than inputs found by asking
// the decoder what works. They pin the meaning of saved inputs across 1.x.
@Suite("1.x input decoding")
struct DecodingCompatibilityTests {
    @Test("Integers consume bytes from the back, most significant first")
    func integers() {
        var full = FuzzedDataProvider([1, 2, 3, 4, 5, 6, 7, 8])
        #expect(full.integer(UInt64.self) == 0x0807_0605_0403_0201)
        #expect(full.isEmpty)

        var short = FuzzedDataProvider([0x12, 0x34])
        #expect(short.integer(UInt32.self) == 0x3412)
        #expect(short.isEmpty)
        #expect(short.integer(UInt64.self) == 0)

        var signed = FuzzedDataProvider([0xFF])
        #expect(signed.integer(Int8.self) == -1)
        #expect(signed.isEmpty)
    }

    @Test("Bounded integers retain full-width consumption and modulo mapping")
    func boundedIntegers() {
        var unsigned = FuzzedDataProvider([0xAA, 0x34, 0x12])
        #expect(unsigned.integer(in: UInt16(10)...20) == 17)
        #expect(unsigned.remainingBytes() == [0xAA])

        var signed = FuzzedDataProvider([0xAA, 0xFF])
        #expect(signed.integer(in: Int8(-10)...10) == -7)
        #expect(signed.remainingBytes() == [0xAA])

        var wide = FuzzedDataProvider([0xAA, 1, 0, 0, 0, 0, 0, 0, 0])
        #expect(wide.integer(in: UInt64(0)...2) == 1)
        #expect(wide.remainingBytes() == [0xAA])

        var singleton = FuzzedDataProvider([0xAA, 0xBB])
        #expect(singleton.integer(in: UInt16(7)...7) == 7)
        #expect(singleton.remainingBytes() == [0xAA, 0xBB])

        var empty = FuzzedDataProvider([])
        #expect(empty.integer(in: UInt16(10)...20) == 10)
    }

    @Test("Booleans consume a whole byte and test its low bit")
    func booleans() {
        var data = FuzzedDataProvider([0xAA, 2, 3])
        #expect(data.bool() == true)
        #expect(data.bool() == false)
        #expect(data.remainingBytes() == [0xAA])
        #expect(data.bool() == false)
    }

    @Test("Floating-point values preserve their input bit patterns")
    func floatingPoint() {
        var single = FuzzedDataProvider([0, 0, 0x80, 0x3F])
        #expect(single.value(Float.self).bitPattern == 0x3F80_0000)
        #expect(single.isEmpty)
        var double = FuzzedDataProvider([1, 0, 0, 0, 0, 0, 0xF8, 0x7F])
        #expect(double.value(Double.self).bitPattern == 0x7FF8_0000_0000_0001)
        #expect(double.isEmpty)
        var probability = FuzzedDataProvider([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        #expect(probability.probability() == 1)
        #expect(probability.isEmpty)
        #expect(probability.probability() == 0)
    }

    @Test("Chunks consume a UInt16 length bounded by the input before the draw")
    func chunks() {
        var data = FuzzedDataProvider([0x41, 0x42, 0x43, 0x44, 2, 0])
        #expect(data.chunk() == [0x41, 0x42])
        #expect(data.remainingBytes() == [0x43, 0x44])
        // Four bytes initially remain: 7 % (4 + 1) selects two, not one.
        var bounded = FuzzedDataProvider([0x41, 0x42, 7, 0])
        #expect(bounded.chunk() == [0x41, 0x42])
        #expect(bounded.isEmpty)
        var short = FuzzedDataProvider([0xFF])
        #expect(short.chunk() == [])
        #expect(short.isEmpty)
    }

    @Test("Text repairs UTF-8 and leaves the unused payload")
    func text() {
        var data = FuzzedDataProvider([0xFF, 0x41, 0x42, 2, 0])
        #expect(data.text() == "\u{FFFD}A")
        #expect(data.remainingText() == "B")
        #expect(data.isEmpty)
        var string = FuzzedDataProvider([0xFF, 0x41, 0x42, 2, 0])
        #expect(string.value(String.self) == "\u{FFFD}A")
        #expect(string.remainingBytes() == [0x42])
    }

    struct ChoiceFixture: Sendable {
        let count: Int
        let input: [UInt8]
        let expected: Int?
        let remaining: [UInt8]
    }

    @Test("Compact indices have stable widths, ordering and exhaustion", arguments: [
        ChoiceFixture(count: 0, input: [0xAA, 0xBB], expected: nil, remaining: [0xAA, 0xBB]),
        ChoiceFixture(count: 1, input: [0xAA, 0xBB], expected: 0, remaining: [0xAA, 0xBB]),
        ChoiceFixture(count: 2, input: [0xAA, 0xFF], expected: 1, remaining: [0xAA]),
        ChoiceFixture(count: 3, input: [0xAA, 0xBB, 0xFF], expected: 0, remaining: [0xAA, 0xBB]),
        ChoiceFixture(count: 3, input: [], expected: 0, remaining: []),
        ChoiceFixture(count: 256, input: [0xAA, 0xFF], expected: 255, remaining: [0xAA]),
        ChoiceFixture(count: 257, input: [0xAA, 0x34, 0x12], expected: 34, remaining: [0xAA]),
        ChoiceFixture(count: 65_536, input: [0xAA, 0xFF, 0xFF], expected: 65_535, remaining: [0xAA]),
        ChoiceFixture(count: 65_537, input: [0xAA, 0, 0, 1], expected: 65_536, remaining: [0xAA]),
        ChoiceFixture(count: 65_537, input: [0x12, 0x34], expected: 0x3412, remaining: []),
        ChoiceFixture(count: 16_777_216, input: [0xAA, 0xFF, 0xFF, 0xFF], expected: 16_777_215, remaining: [0xAA]),
        ChoiceFixture(count: 16_777_217, input: [0xAA, 0, 0, 0, 1], expected: 16_777_216, remaining: [0xAA]),
        ChoiceFixture(count: Int.max, input: [0xAA] + Array(repeating: 0xFF, count: MemoryLayout<Int>.size), expected: 1, remaining: [0xAA]),
    ])
    func compactChoices(_ fixture: ChoiceFixture) {
        var data = FuzzedDataProvider(fixture.input)
        // A range exercises large counts without allocating that many elements.
        #expect(data.element(of: 0..<fixture.count) == fixture.expected)
        #expect(data.remainingBytes() == fixture.remaining)
    }

    @Test("Collection indices need not start at zero")
    func collectionSlice() {
        let choices = ["ignored", "a", "b", "c"].dropFirst()
        var data = FuzzedDataProvider([0xAA, 0xBB, 2])
        #expect(data.bytes(1) == [0xAA])
        #expect(data.element(of: choices) == "c")
        #expect(data.remainingBytes() == [0xBB])
    }

    @Test("caseOf uses compact selection and the declared allCases order")
    func cases() {
        enum Choice: CaseIterable {
            case first, second, third
            static let allCases: [Choice] = [.third, .first, .second]
        }
        enum Singleton: CaseIterable { case only }
        enum Empty: CaseIterable {}
        var data = FuzzedDataProvider([0xAA, 2])
        #expect(data.caseOf(Choice.self) == .second)
        #expect(data.caseOf(Singleton.self) == .only)
        #expect(data.caseOf(Empty.self) == nil)
        #expect(data.remainingBytes() == [0xAA])
        #expect(data.caseOf(Choice.self) == .third)
    }

    struct OptionalTextFixture: Sendable {
        let input: [UInt8]
        let expected: String?
        let remaining: [UInt8]
    }

    @Test("Optional text has an independent presence flag", arguments: [
        OptionalTextFixture(input: [], expected: nil, remaining: []),
        OptionalTextFixture(input: [0x41, 0], expected: nil, remaining: [0x41]),
        OptionalTextFixture(input: [0x41, 2], expected: nil, remaining: [0x41]),
        OptionalTextFixture(input: [1], expected: "", remaining: []),
        OptionalTextFixture(input: [0x41, 0x42, 0, 0, 1], expected: "", remaining: [0x41, 0x42]),
        OptionalTextFixture(input: [0x41, 0x42, 1, 0, 1], expected: "A", remaining: [0x42]),
        OptionalTextFixture(input: [0x41, 1, 0, 3], expected: "A", remaining: []),
        OptionalTextFixture(input: [0xFF, 1, 0, 1], expected: "\u{FFFD}", remaining: []),
    ])
    func optionalText(_ fixture: OptionalTextFixture) {
        var direct = FuzzedDataProvider(fixture.input)
        #expect(direct.optionalText() == fixture.expected)
        #expect(direct.remainingBytes() == fixture.remaining)
        var value = FuzzedDataProvider(fixture.input)
        #expect(value.value(String?.self) == fixture.expected)
        #expect(value.remainingBytes() == fixture.remaining)
    }

    @Test("Fuzzable arrays and optionals preserve their framing")
    func composites() {
        var bytes = FuzzedDataProvider([0x11, 0x22, 0x33, 2])
        #expect(bytes.value([UInt8].self) == [0x33, 0x22])
        #expect(bytes.remainingBytes() == [0x11])
        var strings = FuzzedDataProvider([0x41, 0x42, 1, 0, 1, 0, 2])
        #expect(strings.value([String].self) == ["A", "B"])
        #expect(strings.isEmpty)
        var optional = FuzzedDataProvider([0xAA, 0x2A, 1])
        #expect(optional.value(UInt8?.self) == 42)
        #expect(optional.remainingBytes() == [0xAA])
    }

    @Test("Compact selection and optional text compose with following fields")
    func composedRequest() {
        enum Method: CaseIterable { case get, post, patch }
        struct Request: Fuzzable {
            let method: Method
            let path: String?
            let flag: Bool
            let payload: [UInt8]
            init(from data: inout FuzzedDataProvider) {
                method = data.caseOf() ?? .get
                path = data.optionalText()
                flag = data.bool()
                payload = data.remainingBytes()
            }
        }
        var data = FuzzedDataProvider([0x2F, 0x78, 0x42, 1, 2, 0, 1, 2])
        let request = data.value(Request.self)
        #expect(request.method == .patch)
        #expect(request.path == "/x")
        #expect(request.flag)
        #expect(request.payload == [0x42])
        #expect(data.isEmpty)
    }
}
