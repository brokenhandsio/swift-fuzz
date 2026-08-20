/// A single fuzzing entry point: a name, and a closure that consumes one
/// fuzzer-produced input.
///
/// Creating a `FuzzTarget` registers it. You never store the result — declare
/// targets inside the well-known `fuzzTargets` closure and the generated entry
/// point will reach them:
///
/// ```swift
/// import Fuzzing
/// import MyLibrary
///
/// let fuzzTargets: @Sendable () -> Void = {
///     FuzzTarget("JSONParsing") { bytes in
///         _ = try? JSONParser.parse(bytes)
///     }
/// }
/// ```
///
/// The closure is called millions of times with arbitrary, mostly-malformed
/// input. It should not print, and it must not exit the process except to
/// signal a genuine finding — a trap, `fatalError`, or a failed precondition
/// are all reported by libFuzzer as crashes, which is exactly the point.
///
/// - Note: `bytes` is only valid for the duration of the call. Copy anything
///   you need to keep.
/// Storing a closure that takes an unsafe buffer is not itself unsafe — the
/// pointer only exists during a call. `@safe` records that; the unsafety is
/// confined to ``FuzzRunner/run(_:_:)``, where the buffer is constructed.
@safe
public struct FuzzTarget: Sendable {
    /// The target's name, as passed to `swift package fuzz <name>`.
    public let name: String

    /// The body invoked once per fuzzer-produced input.
    ///
    /// The closure's parameter is an unsafe buffer because that is libFuzzer's
    /// contract: it hands over a pointer it owns for the duration of one call.
    public let body: @Sendable (UnsafeRawBufferPointer) -> Void

    /// Creates and registers a fuzz target.
    ///
    /// - Parameters:
    ///   - name: A unique name. Used to select the target and to name its
    ///     corpus, dictionary and crash directories.
    ///   - body: The code under test.
    @discardableResult
    public init(
        _ name: String,
        _ body: @escaping @Sendable (UnsafeRawBufferPointer) -> Void
    ) {
        self.name = name
        unsafe self.body = body
        FuzzRunner.register(self)
    }

    /// Creates and registers a fuzz target that reads typed values instead of
    /// raw bytes.
    ///
    /// ```swift
    /// FuzzTarget.structured("Decode") { data in
    ///     let depth = data.integer(in: 1...64)
    ///     _ = try? MyParser.parse(data.remainingBytes(), maximumDepth: depth)
    /// }
    /// ```
    ///
    /// This is a factory rather than an overload of ``init(_:_:)`` because two
    /// initialisers taking a closure are ambiguous whenever the parameter type
    /// cannot be inferred — `{ _ in }` is enough to break it, and the compiler
    /// points at the closure rather than at the choice between them.
    ///
    /// Prefer this form in a package with `.strictMemorySafety()` enabled: the
    /// provider owns the unsafe buffer, so the harness needs no `unsafe`.
    @discardableResult
    public static func structured(
        _ name: String,
        _ body: @escaping @Sendable (inout FuzzedDataProvider) -> Void
    ) -> FuzzTarget {
        unsafe FuzzTarget(name) { bytes in
            var provider = unsafe FuzzedDataProvider(bytes)
            body(&provider)
        }
    }
}
