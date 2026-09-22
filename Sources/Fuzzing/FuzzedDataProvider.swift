/// Turns one fuzzer-produced input into typed values.
///
/// A fuzz body receives arbitrary bytes; most harnesses want an integer here, a
/// bool there, and the rest as a payload. Doing that by hand means slicing and
/// bounds-checking in every target, which is where the LLVM equivalent
/// (`FuzzedDataProvider.h`) came from. This is the same idea in Swift.
///
/// ```swift
/// FuzzTarget.structured("Decode") { data in
///     let depth = data.integer(in: 1...64)
///     let strict = data.bool()
///     _ = try? MyParser.parse(data.remainingBytes(), maximumDepth: depth, strict: strict)
/// }
/// ```
///
/// ### Running out of data
///
/// Nothing here fails or traps when the input is short: integers come back as
/// zero, `bool()` as `false`, byte requests are truncated. A fuzzer spends most
/// of its time on tiny inputs, so a provider that threw would turn the common
/// case into an error path and the harness into a mass of `guard`s.
///
/// ### Where values are taken from
///
/// Bytes are taken from the **front** and control values — integers, bools,
/// enum cases — from the **back**. That is deliberate, and copied from LLVM's
/// version: it keeps the payload contiguous at a stable offset, so when the
/// fuzzer mutates the payload it does not also shift every control value and
/// invalidate what it has learned about them.
///
/// The provider owns its input and may outlive the fuzz body. Copies share
/// immutable input storage, but consume bytes independently. For a borrowed,
/// zero-copy input, use the `Span` form of ``FuzzTarget`` instead.
public struct FuzzedDataProvider: Sendable {
    private let storage: [UInt8]
    /// Next byte to hand out from the front.
    private var head: Int
    /// One past the next byte to hand out from the back.
    private var tail: Int

    /// Creates a provider that owns the input bytes.
    ///
    /// Array value semantics keep the input unchanged if the caller later
    /// modifies its array. Copying a provider preserves its consumption
    /// position; subsequent reads advance only the copy being read.
    public init(_ bytes: [UInt8]) {
        self.storage = bytes
        self.head = 0
        self.tail = bytes.count
    }

    /// How many bytes remain unconsumed.
    public var remainingCount: Int { max(0, tail - head) }

    /// Whether the input is exhausted.
    public var isEmpty: Bool { remainingCount == 0 }

    // MARK: - Bytes, taken from the front

    /// Consumes up to `count` bytes. Returns fewer if the input is short.
    public mutating func bytes(_ count: Int) -> [UInt8] {
        let available = min(max(0, count), remainingCount)
        guard available > 0 else { return [] }
        let result = Array(storage[head..<(head + available)])
        head += available
        return result
    }

    /// Consumes everything that is left.
    public mutating func remainingBytes() -> [UInt8] {
        bytes(remainingCount)
    }

    /// Consumes a length, then that many bytes.
    ///
    /// The idiom for a harness that needs several values out of one input: the
    /// length is a control value from the back, the bytes come off the front,
    /// so the payload stays contiguous and mutating it does not shift the
    /// values already drawn.
    ///
    /// The length is drawn against what is left, not against a fixed ceiling.
    ///
    /// That distinction is the whole of it. A length drawn from `0...255`
    /// sounds bounded, but on any input shorter than 255 bytes the drawn value
    /// almost always exceeds what remains, so the first chunk takes everything
    /// and every later draw returns empty. A harness pulling three header
    /// values out of a 46-byte input got 45 bytes, then nothing, then nothing —
    /// silently fuzzing one field and leaving the other two constant.
    ///
    /// Drawing against `remainingCount` hands the split back to the fuzzer.
    /// The length is a control value at a stable offset, so coverage feedback
    /// can learn to move it, which is exactly what the front/back split exists
    /// for. There is no allocation risk in the wider bound either: the ceiling
    /// is the input, and libFuzzer already bounds that with `-max_len`.
    public mutating func chunk() -> [UInt8] {
        // Two bytes, whatever the input size, so the layout a fuzzer learns
        // does not shift as the corpus grows. Inputs beyond 64KB cap here;
        // `remainingBytes()` is the way to ask for the rest.
        let limit = UInt16(clamping: remainingCount)
        return bytes(Int(integer(in: 0...limit)))
    }

    /// Consumes a ``chunk()`` as UTF-8 text.
    ///
    /// Invalid sequences become replacement characters rather than failing: the
    /// point is to reach the code under test, and the replacement character is
    /// itself worth testing — text handling frequently goes wrong on it.
    public mutating func text() -> String {
        String(decoding: chunk(), as: UTF8.self)
    }

    /// Consumes a ``chunk()`` as UTF-8 text, or `nil` if the chunk is empty.
    ///
    /// For APIs where absent and present-but-empty differ — a URL with no
    /// scheme is not a URL whose scheme is `""` — so an empty chunk tests the
    /// former rather than accidentally testing the latter.
    public mutating func optionalText() -> String? {
        let chunk = chunk()
        return chunk.isEmpty ? nil : String(decoding: chunk, as: UTF8.self)
    }

    /// Consumes everything that is left, as UTF-8 text.
    public mutating func remainingText() -> String {
        String(decoding: remainingBytes(), as: UTF8.self)
    }

    // MARK: - Control values, taken from the back

    /// Consumes a value of `type`, using its full range.
    ///
    /// Consumes at most `MemoryLayout<T>.size` bytes, and fewer if that is all
    /// there is — so a short input yields a small value rather than failing.
    public mutating func integer<T: FixedWidthInteger>(_ type: T.Type = T.self) -> T {
        // Only bytes that exist are consumed. Padding a short input out to the
        // full width would shift the real byte into the high bits and turn a
        // one-byte input into an enormous value — the opposite of what a
        // harness wants when the fuzzer is exploring small inputs.
        var result: T = 0
        for _ in 0..<Swift.min(MemoryLayout<T>.size, remainingCount) {
            result = (result << 8) | T(truncatingIfNeeded: takeFromBack())
        }
        return result
    }

    /// Consumes a value within `range`, inclusive.
    ///
    /// The result is uniform over the range only when the range's size is a
    /// power of two; otherwise it is the remainder, which skews slightly toward
    /// the low end. That trade is deliberate — it costs one modulo instead of
    /// rejection sampling, which would consume an unpredictable number of bytes
    /// and make inputs harder for the fuzzer to mutate meaningfully.
    public mutating func integer<T: FixedWidthInteger>(in range: ClosedRange<T>) -> T {
        guard range.lowerBound != range.upperBound else { return range.lowerBound }
        let span = T.Magnitude(truncatingIfNeeded: range.upperBound &- range.lowerBound)
        // A full-width span cannot be represented as span + 1, and needs no
        // reduction anyway.
        guard span != T.Magnitude.max else { return integer(T.self) }
        let offset = magnitude(T.self) % (span + 1)
        return range.lowerBound &+ T(truncatingIfNeeded: offset)
    }

    /// Consumes one bit's worth of input.
    public mutating func bool() -> Bool {
        integer(UInt8.self) & 1 == 1
    }

    /// Consumes a value in `0...1`.
    public mutating func probability() -> Double {
        Double(integer(UInt64.self)) / Double(UInt64.max)
    }

    /// Consumes an index and returns that element, or `nil` if `collection` is
    /// empty.
    public mutating func element<C: Collection>(of collection: C) -> C.Element? {
        guard !collection.isEmpty else { return nil }
        let offset = Int(integer(in: 0...UInt64(collection.count - 1)))
        return collection[collection.index(collection.startIndex, offsetBy: offset)]
    }

    /// Consumes a case of `type`, or `nil` if it has none.
    public mutating func caseOf<T: CaseIterable>(_ type: T.Type = T.self) -> T? {
        element(of: Array(T.allCases))
    }

    /// Consumes a value of a ``Fuzzable`` type.
    public mutating func value<T: Fuzzable>(_ type: T.Type = T.self) -> T {
        T(from: &self)
    }

    // MARK: - Private

    private mutating func takeFromBack() -> UInt8 {
        guard tail > head else { return 0 }
        tail -= 1
        return storage[tail]
    }

    private mutating func magnitude<T: FixedWidthInteger>(_ type: T.Type) -> T.Magnitude {
        var result: T.Magnitude = 0
        for _ in 0..<Swift.min(MemoryLayout<T>.size, remainingCount) {
            result = (result << 8) | T.Magnitude(truncatingIfNeeded: takeFromBack())
        }
        return result
    }
}
