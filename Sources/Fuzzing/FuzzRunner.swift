#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// The registry the generated entry point talks to.
///
/// You do not normally call any of this directly. `FuzzTargetPlugin` generates
/// a small shim that calls ``initialize()`` from `LLVMFuzzerInitialize` and
/// ``run(_:_:)`` from `LLVMFuzzerTestOneInput`.
///
/// ### Concurrency
///
/// libFuzzer registers targets once, on the single thread that runs
/// `LLVMFuzzerInitialize`, before any input is dispatched; parallel fuzzing
/// (`-jobs`/`-workers`) uses separate *processes*, not threads. The mutable
/// state below is therefore confined to that single-threaded startup phase and
/// is read-only afterwards, which is why it is `nonisolated(unsafe)` rather
/// than locked — a lock on ``run(_:_:)`` would be taken millions of times per
/// second for no benefit.
public enum FuzzRunner {
    /// Every target registered by the `fuzzTargets` closure.
    nonisolated(unsafe) private static var registered: [FuzzTarget] = []

    /// The target selected by ``initialize()``. Read once per input.
    nonisolated(unsafe) private static var selected: (@Sendable (UnsafeRawBufferPointer) -> Void)?

    /// Registers a target. Called by ``FuzzTarget/init(_:_:)``.
    public static func register(_ target: FuzzTarget) {
        registered.append(target)
    }

    /// The names of all registered targets, in declaration order.
    public static var registeredNames: [String] {
        registered.map(\.name)
    }

    /// Chooses which registered target will receive input.
    ///
    /// Selection comes from the `FUZZ_TARGET` environment variable. libFuzzer
    /// rejects unknown `-`-prefixed arguments, so the command line is not
    /// available to us for this.
    ///
    /// When `FUZZ_TARGET` is unset and exactly one target is registered, that
    /// target is used — the common case of one target per executable.
    ///
    /// - Note: Called from `LLVMFuzzerInitialize`. Terminates the process with
    ///   an explanatory message if selection is ambiguous or impossible; there
    ///   is no useful way to continue.
    public static func initialize() {
        guard !registered.isEmpty else {
            fail("""
                No fuzz targets were registered.
                Declare at least one inside the `fuzzTargets` closure:

                    let fuzzTargets: @Sendable () -> Void = {
                        FuzzTarget("MyTarget") { bytes in ... }
                    }
                """)
        }

        let requested = environmentValue("FUZZ_TARGET")

        switch (requested, registered.count) {
        case (nil, 1):
            selected = registered[0].body
        case (nil, _):
            fail("""
                FUZZ_TARGET is not set and this executable registers \(registered.count) targets.
                Available: \(registeredNames.joined(separator: ", "))
                Run one with: swift package fuzz <name>
                """)
        case (let name?, _):
            guard let match = registered.first(where: { $0.name == name }) else {
                fail("""
                    No fuzz target named "\(name)".
                    Available: \(registeredNames.joined(separator: ", "))
                    """)
            }
            selected = match.body
        }
    }

    /// Dispatches one input to the selected target.
    ///
    /// - Returns: `0`, always — libFuzzer treats any non-zero return as a
    ///   request to reject the input from the corpus, which is not something
    ///   this API exposes yet.
    public static func run(_ data: UnsafeRawPointer?, _ size: Int) -> CInt {
        guard let selected else {
            fail("FuzzRunner.run was called before FuzzRunner.initialize.")
        }
        // A zero-length input still yields a valid (null-base, count 0) buffer.
        selected(UnsafeRawBufferPointer(start: data, count: size))
        return 0
    }

    private static func environmentValue(_ key: String) -> String? {
        guard let raw = getenv(key) else { return nil }
        let value = String(cString: raw)
        return value.isEmpty ? nil : value
    }

    private static func fail(_ message: String) -> Never {
        // Written straight to stderr: this runs inside libFuzzer's process and
        // must be legible next to its own output.
        FileHandle.standardError.write("swift-fuzz: \(message)\n")
        exit(1)
    }
}

private enum FileHandle {
    static let standardError = Writer(fd: 2)
    struct Writer {
        let fd: Int32
        func write(_ string: String) {
            let bytes = Array(string.utf8)
            bytes.withUnsafeBufferPointer { buffer in
                var written = 0
                while written < buffer.count {
                    let n = _write(fd, buffer.baseAddress! + written, buffer.count - written)
                    if n <= 0 { break }
                    written += n
                }
            }
        }
    }
}

#if canImport(Darwin)
private let _write = Darwin.write
#else
private let _write = Glibc.write
#endif
