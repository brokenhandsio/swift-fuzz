import Foundation

/// The environment every fuzz binary is run with.
///
/// One place, because the three run paths — fuzzing, coverage and minimization —
/// have to agree. They previously each built their own and drifted.
enum FuzzEnvironment {
    /// `base` is a parameter so this is testable without mutating the
    /// process's own environment.
    static func make(
        target: String?,
        symbolizer: URL?,
        listTargets: Bool = false,
        base: [String: String] = ProcessInfo.processInfo.environment
    ) -> [String: String] {
        var environment = base

        if let target { environment["FUZZ_TARGET"] = target }
        if listTargets { environment["FUZZ_LIST_TARGETS"] = "1" }

        #if !os(macOS)
        // Swift's crash handler otherwise runs instead of libFuzzer's, which
        // means the crashing input is never written and the exit code is a
        // bare signal. Findings would be visible in the log and lost on disk.
        environment["SWIFT_BACKTRACE"] = "enable=no"
        #endif

        // The sanitizer runtime turns addresses into names by launching
        // llvm-symbolizer, and it only finds one on PATH. A toolchain selected
        // with TOOLCHAINS or xcrun frequently is not on PATH, and the failure
        // is both late and unreadable: coverage reports nothing at all, and
        // crash traces lose their file and line. We know where the toolchain
        // is because we just built with it, so point at it directly.
        //
        // An existing value wins: someone who set this meant it.
        if environment["ASAN_SYMBOLIZER_PATH"] == nil, let symbolizer {
            environment["ASAN_SYMBOLIZER_PATH"] = symbolizer.path
        }

        return environment
    }

    /// Whether a symbolizer will be available to the binaries we run.
    static func hasSymbolizer(_ environment: [String: String]) -> Bool {
        guard let path = environment["ASAN_SYMBOLIZER_PATH"] else { return false }
        return FileManager.default.isExecutableFile(atPath: path)
    }
}
