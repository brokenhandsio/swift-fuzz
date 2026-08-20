/// A tiny parser with a deliberately planted bug, used as swift-fuzz's own
/// end-to-end test. The bug is reachable from a short input so the loop is fast.
///
/// It takes `[UInt8]` rather than the `UnsafeRawBufferPointer` the fuzzer hands
/// over, which is how a real library is shaped: the harness converts at the
/// boundary, so the unsafe type never reaches the code under test. Under
/// `.strictMemorySafety()` that keeps the whole library free of `unsafe`.
public enum BuggyLibrary {
    public enum ParseError: Error { case tooShort }

    public static func parse(_ bytes: [UInt8]) throws {
        guard bytes.count >= 4 else { throw ParseError.tooShort }
        // Planted: a specific 4-byte header trips a trap rather than an error.
        if bytes[0] == 0x46, bytes[1] == 0x55, bytes[2] == 0x5A, bytes[3] == 0x5A {
            fatalError("planted bug: unhandled FUZZ header")
        }
    }

    /// An asynchronous entry point, so the examples exercise the async bridge.
    public static func parseAsync(_ bytes: [UInt8]) async throws {
        // A real suspension, so the body genuinely leaves and re-enters the
        // concurrency runtime rather than completing inline.
        await Task.yield()
        try parse(bytes)
    }
}
