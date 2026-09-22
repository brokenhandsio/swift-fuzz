#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// The registry the generated entry point talks to.
///
/// Not part of the public API. `FuzzTargetPlugin` generates a shim that calls
/// ``initialize()`` from `LLVMFuzzerInitialize` and ``run(_:_:)`` from
/// `LLVMFuzzerTestOneInput`; those two are exposed under the `Generated` SPI so
/// the generated file can reach them, and nothing else here escapes the module.
///
/// Keeping this out of the public surface matters for more than tidiness:
/// ``run(_:_:)`` takes an unsafe pointer, and it is the only such signature
/// left. A user who never sees it cannot misuse it, and a 1.0 does not freeze
/// it.
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
@_spi(Generated) public enum FuzzRunner {
    /// Every target registered by the `fuzzTargets` closure.
    @safe nonisolated(unsafe) private static var registered: [FuzzTarget] = []

    /// The target selected by ``initialize()``. Read once per input.
    @safe nonisolated(unsafe) private static var selected: (@Sendable (UnsafeRawBufferPointer) -> Void)?

    /// How long an asynchronous fuzz body may take before it is treated as
    /// stalled, in seconds.
    ///
    /// Override with `FUZZ_ASYNC_TIMEOUT`. Generous by default: a false
    /// positive aborts a run that was merely slow, which is worse than waiting.
    static var asyncTimeout: Int {
        environmentValue("FUZZ_ASYNC_TIMEOUT").flatMap(Int.init) ?? 60
    }

    /// Called when an asynchronous body has not finished in time.
    ///
    /// Aborts rather than returning, so libFuzzer records the input alongside
    /// the explanation — a stalled input is worth keeping even when the cause
    /// turns out to be the harness.
    static func reportStall() -> Never {
        fail("""
            An asynchronous fuzz body did not finish within \(asyncTimeout)s.

            The usual cause is work that requires the main actor. libFuzzer runs on the
            main thread and swift-fuzz blocks it while the body runs, so an
            `await MainActor.run { ... }` inside the body waits for a thread that is
            waiting for it.

            If the body is simply slow, raise the limit:
                FUZZ_ASYNC_TIMEOUT=300 swift package fuzz <target>
            """)
    }

    /// Registers a target. Called by ``FuzzTarget/init(_:_:)``.
    static func register(_ target: FuzzTarget) {
        if let error = TargetIdentity.validationError(registeredNames + [target.name]) {
            fail(error)
        }
        registered.append(target)
    }

    /// The names of all registered targets, in declaration order.
    static var registeredNames: [String] {
        registered.map(\.name)
    }

    /// Chooses which registered target will receive input.
    ///
    /// Selection comes from the `FUZZ_TARGET` environment variable. libFuzzer
    /// rejects unknown `-`-prefixed arguments, so the command line is not
    /// available to us for this.
    ///
    /// When `FUZZ_TARGET` is unset, an executable basename matching a logical
    /// name selects that target. This lets OSS-Fuzz run each exported binary
    /// directly. Otherwise a sole registration is used.
    ///
    /// - Note: Called from `LLVMFuzzerInitialize`. Terminates the process with
    ///   an explanatory message if selection is ambiguous or impossible; there
    ///   is no useful way to continue.
    @_spi(Generated) public static func initialize() {
        // Asked by `swift package fuzz` to discover what this executable
        // registers. The registry is the only source of truth for that — the
        // names live in a closure, so nothing outside the process can know them
        // without asking. Printed one per line, then exit before fuzzing starts.
        if environmentValue("FUZZ_LIST_TARGETS") != nil {
            FileHandle.standardOutput.write(registeredNames.joined(separator: "\n") + "\n")
            exit(0)
        }

        guard !registered.isEmpty else {
            fail("""
                No fuzz targets were registered.
                Declare at least one inside the `fuzzTargets` closure:

                    let fuzzTargets: @Sendable () -> Void = {
                        FuzzTarget("MyTarget") { bytes in ... }
                    }
                """)
        }

        let requested = targetSelector(
            explicit: environmentValue("FUZZ_TARGET"),
            executable: executablePath(), names: registeredNames)

        switch (requested, registered.count) {
        case (nil, 1):
            unsafe selected = registered[0].body
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
            unsafe selected = match.body
        }
    }

    static func targetSelector(explicit: String?, executable: String, names: [String]) -> String? {
        if let explicit { return explicit }
        let basename = executable.split(separator: "/").last.map(String.init) ?? ""
        return names.contains(basename) ? basename : nil
    }

    private static func executablePath() -> String {
        #if os(Linux)
        // A C libFuzzer main does not initialize Swift's CommandLine state.
        // /proc identifies the actual exported executable even under a launcher
        // that changes argv[0], as OSS-Fuzz's build checks do.
        var buffer = [CChar](repeating: 0, count: 4096)
        let count = unsafe buffer.withUnsafeMutableBufferPointer { pointer in
            unsafe readlink("/proc/self/exe", pointer.baseAddress!, pointer.count)
        }
        if count > 0, count < buffer.count {
            return String(decoding: buffer.prefix(count).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
        #endif
        return CommandLine.arguments.first ?? ""
    }

    /// Dispatches one input to the selected target.
    ///
    /// - Returns: `0`, always — libFuzzer treats any non-zero return as a
    ///   request to reject the input from the corpus, which is not something
    ///   this API exposes yet.
    @_spi(Generated) public static func run(_ data: UnsafeRawPointer?, _ size: Int) -> CInt {
        guard let selected else {
            fail("FuzzRunner.run was called before FuzzRunner.initialize.")
        }
        // The one genuinely unsafe step: libFuzzer guarantees `data` is valid for
        // `size` bytes for the duration of this call, and the buffer never escapes
        // it. A zero-length input still yields a valid (null-base, count 0) buffer.
        unsafe selected(UnsafeRawBufferPointer(start: data, count: size))
        return 0
    }

    private static func environmentValue(_ key: String) -> String? {
        // `getenv` hands back a pointer into the environment block, which is
        // valid until the environment is mutated. It is copied into a String
        // immediately and never retained.
        guard let raw = unsafe getenv(key) else { return nil }
        let value = unsafe String(cString: raw)
        return value.isEmpty ? nil : value
    }

    static func fail(_ message: String) -> Never {
        // Written straight to stderr: this runs inside libFuzzer's process and
        // must be legible next to its own output.
        FileHandle.standardError.write("swift-fuzz: \(message)\n")
        exit(1)
    }
}

private enum FileHandle {
    static let standardOutput = Writer(fd: 1)
    static let standardError = Writer(fd: 2)
    struct Writer {
        let fd: Int32
        func write(_ string: String) {
            let bytes = Array(string.utf8)
            // Writing to fd 2 directly keeps this usable from inside libFuzzer's
            // process without pulling in Foundation. The buffer is owned by
            // `bytes` and does not outlive the closure.
            unsafe bytes.withUnsafeBufferPointer { buffer in
                var written = 0
                while written < buffer.count {
                    let n = unsafe _write(fd, buffer.baseAddress! + written, buffer.count - written)
                    if n <= 0 { break }
                    written += n
                }
            }
        }
    }
}

// The platform `write(2)`, bound once so the writer above stays portable.
#if canImport(Darwin)
private let _write = unsafe Darwin.write
#else
private let _write = unsafe Glibc.write
#endif
