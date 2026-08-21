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
    /// Where the input lives.
    ///
    /// The synchronous forms borrow libFuzzer's buffer and copy nothing, which
    /// matters when the body is short and the loop runs a million times a
    /// second. The asynchronous forms have to copy anyway — the bytes must
    /// outlive the call to cross into a `Task` — so they own an array instead.
    @safe private enum Storage {
        case borrowed(UnsafeRawBufferPointer)
        case owned([UInt8])
    }

    @safe private let storage: Storage
    /// Next byte to hand out from the front.
    private var head: Int
    /// One past the next byte to hand out from the back.
    private var tail: Int

    /// Wraps a fuzzer-produced buffer.
    ///
    /// Internal: the public way to get a provider is `FuzzTarget.structured`,
    /// which builds one per input, or ``init(_:)`` for bytes you already own.
    init(_ bytes: UnsafeRawBufferPointer) {
        unsafe self.storage = .borrowed(bytes)
        self.head = 0
        self.tail = bytes.count
    }

    /// Wraps bytes the provider owns.
    ///
    /// Used by the asynchronous fuzz targets, where the input has to outlive
    /// the synchronous call that libFuzzer makes.
    public init(_ bytes: [UInt8]) {
        self.storage = .owned(bytes)
        self.head = 0
        self.tail = bytes.count
    }

    private func byte(at index: Int) -> UInt8 {
        switch storage {
        case .borrowed(let buffer): unsafe buffer[index]
        case .owned(let bytes): bytes[index]
        }
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
        let result: [UInt8]
        switch storage {
        case .borrowed(let buffer):
            result = unsafe [UInt8](buffer[head..<(head + available)])
        case .owned(let bytes):
            result = Array(bytes[head..<(head + available)])
        }
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
    /// Bounded at 255 bytes per chunk, so a single byte of input cannot ask for
    /// the whole buffer and starve everything drawn after it.
    public mutating func chunk() -> [UInt8] {
        bytes(Int(integer(in: UInt8.min...UInt8.max)))
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
        return byte(at: tail)
    }

    private mutating func magnitude<T: FixedWidthInteger>(_ type: T.Type) -> T.Magnitude {
        var result: T.Magnitude = 0
        for _ in 0..<Swift.min(MemoryLayout<T>.size, remainingCount) {
            result = (result << 8) | T.Magnitude(truncatingIfNeeded: takeFromBack())
        }
        return result
    }
}
