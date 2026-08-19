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
public struct FuzzTarget: Sendable {
    /// The target's name, as passed to `swift package fuzz <name>`.
    public let name: String

    /// The body invoked once per fuzzer-produced input.
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
        self.body = body
        FuzzRunner.register(self)
    }
}
