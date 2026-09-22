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
/// The input arrives as a `Span<UInt8>`: bounds-checked, and non-escapable, so
/// the compiler enforces that it does not outlive the call. Copy anything you
/// need to keep. If you need a pointer for an API that cannot take a `Span`,
/// ask the span for one with `withUnsafeBufferPointer(_:)`.
///
/// Marked `@safe` because holding a closure that takes libFuzzer's buffer is
/// not itself unsafe — the pointer exists only during a call, inside
/// `FuzzRunner.run`.
@safe
public struct FuzzTarget: Sendable {
    /// The target's name, as passed to `swift package fuzz <name>`.
    public let name: String

    /// The body invoked once per input.
    ///
    /// Deliberately not public. It takes libFuzzer's raw buffer because that is
    /// what the generated entry point has to hand; no public API on this type
    /// exposes an unsafe pointer.
    let body: @Sendable (UnsafeRawBufferPointer) -> Void

    /// Creates and registers a fuzz target.
    ///
    /// - Parameters:
    ///   - name: A unique name. Used to select the target and to name its
    ///     corpus, dictionary and crash directories.
    ///   - body: The code under test.
    @discardableResult
    public init(
        _ name: String,
        _ body: @escaping @Sendable (Span<UInt8>) -> Void
    ) {
        unsafe self.init(name: name, unsafeBytes: { buffer in
            let typed = unsafe buffer.assumingMemoryBound(to: UInt8.self)
            unsafe body(typed.span)
        })
    }

    /// The designated initialiser. Everything else funnels through here.
    ///
    /// The first parameter is labelled so a trailing-closure call cannot match
    /// it: `FuzzTarget("x") { }` would otherwise be ambiguous between this and
    /// ``init(_:_:)``, because a trailing closure matches a final closure
    /// parameter whatever its label.
    init(name: String, unsafeBytes body: @escaping @Sendable (UnsafeRawBufferPointer) -> Void) {
        self.name = name
        unsafe self.body = body
        FuzzRunner.register(self)
    }

    /// Creates and registers a fuzz target whose body receives the input as an
    /// array.
    ///
    /// ```swift
    /// FuzzTarget.bytes("Decode") { bytes in
    ///     _ = try? JSONDecoder().decode(Probe.self, from: Data(bytes))
    /// }
    /// ```
    ///
    /// Use this when the code under test takes a collection — most existing
    /// APIs do. ``init(_:_:)`` hands over a `Span<UInt8>` instead, which copies
    /// nothing and suits an API that can take one directly; this copies once
    /// per execution, which is invisible next to any real parsing work.
    @discardableResult
    public static func bytes(
        _ name: String,
        _ body: @escaping @Sendable ([UInt8]) -> Void
    ) -> FuzzTarget {
        unsafe FuzzTarget(name: name, unsafeBytes: { buffer in
            body(unsafe [UInt8](buffer))
        })
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
    /// The provider owns a copy of the input, so the body may retain it. This
    /// copies once per execution; ``init(_:_:)`` remains the zero-copy form.
    @discardableResult
    public static func structured(
        _ name: String,
        _ body: @escaping @Sendable (inout FuzzedDataProvider) -> Void
    ) -> FuzzTarget {
        unsafe FuzzTarget(name: name, unsafeBytes: { bytes in
            var provider = FuzzedDataProvider(unsafe [UInt8](bytes))
            body(&provider)
        })
    }
}
