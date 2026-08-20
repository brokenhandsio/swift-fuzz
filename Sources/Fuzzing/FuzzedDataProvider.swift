/// Turns one fuzzer-produced input into typed values.
///
/// A fuzz body receives arbitrary bytes; most harnesses want an integer here, a
/// bool there, and the rest as a payload. Doing that by hand means slicing and
/// bounds-checking in every target, which is where the LLVM equivalent
/// (`FuzzedDataProvider.h`) came from. This is the same idea in Swift.
///
/// ```swift
/// FuzzTarget("Decode", providing: { data in
///     let depth = data.integer(in: 1...64)
///     let strict = data.bool()
///     _ = try? MyParser.parse(data.remainingBytes(), maximumDepth: depth, strict: strict)
/// })
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
/// - Note: The provider reads the buffer libFuzzer owns, which is valid only
///   for the duration of one call. Do not let it, or anything it hands back by
///   reference, escape the fuzz body.
@safe
public struct FuzzedDataProvider {
    @safe private let buffer: UnsafeRawBufferPointer
    /// Next byte to hand out from the front.
    private var head: Int
    /// One past the next byte to hand out from the back.
    private var tail: Int

    /// Wraps a fuzzer-produced buffer.
    ///
    /// You do not normally call this: use `FuzzTarget(_:providing:)`, which
    /// builds one per input.
    public init(_ bytes: UnsafeRawBufferPointer) {
        unsafe self.buffer = bytes
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
        let result = unsafe [UInt8](buffer[head..<(head + available)])
        head += available
        return result
    }

    /// Consumes everything that is left.
    public mutating func remainingBytes() -> [UInt8] {
        bytes(remainingCount)
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
        return unsafe buffer[tail]
    }

    private mutating func magnitude<T: FixedWidthInteger>(_ type: T.Type) -> T.Magnitude {
        var result: T.Magnitude = 0
        for _ in 0..<Swift.min(MemoryLayout<T>.size, remainingCount) {
            result = (result << 8) | T.Magnitude(truncatingIfNeeded: takeFromBack())
        }
        return result
    }
}
