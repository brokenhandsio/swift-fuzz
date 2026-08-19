import Foundation
import PackagePlugin

/// Checks that the active toolchain can actually build a fuzz target, before
/// anything expensive happens.
///
/// The check compiles and links a five-line file rather than looking for
/// `libclang_rt.fuzzer*.a` on disk. Path layouts differ across platforms and
/// have changed between toolchain versions — the archives live in
/// `lib/darwin/` on some and `lib/<triple>/` on others, and
/// `clang -print-runtime-dir` disagrees with both on some Linux toolchains.
/// Linking a real binary tests the capability we need and nothing else.
///
/// Linking matters, not just compiling: on macOS a toolchain without libFuzzer
/// rejects `-sanitize=fuzzer` up front, but on Linux the flag is accepted and
/// the failure only appears when the archive cannot be found at link time.
enum Preflight {
    /// Runs the probe, or skips it if this toolchain already passed.
    ///
    /// - Throws: ``FuzzError`` carrying platform-specific installation guidance
    ///   if the toolchain cannot build a fuzz target.
    static func check(context: PluginContext) throws {
        let swiftc = try context.tool(named: "swiftc").url
        let workDirectory = context.pluginWorkDirectoryURL
        let stamp = workDirectory.appending(path: "preflight-ok")
        let identity = toolchainIdentity(swiftc: swiftc)

        // Only success is cached. A toolchain that fails costs one probe per
        // invocation, which is a fraction of the build it saves — and caching a
        // failure would outlive the user fixing it.
        if let cached = try? String(contentsOf: stamp, encoding: .utf8), cached == identity {
            return
        }

        guard probeSucceeds(swiftc: swiftc, workDirectory: workDirectory) else {
            throw FuzzError(FuzzerRuntime.missingToolchainMessage)
        }
        try? identity.write(to: stamp, atomically: true, encoding: .utf8)
    }

    /// Identifies the toolchain by path *and* version.
    ///
    /// Path alone is not enough: `swiftly` swaps what `swift-latest.xctoolchain`
    /// points at, and a toolchain upgraded in place keeps its path.
    private static func toolchainIdentity(swiftc: URL) -> String {
        let version = (try? Process.capture(swiftc, ["--version"])) ?? ""
        return "\(swiftc.path)\n\(version.trimmingCharacters(in: .whitespacesAndNewlines))"
    }

    private static func probeSucceeds(swiftc: URL, workDirectory: URL) -> Bool {
        let source = workDirectory.appending(path: "preflight-probe.swift")
        let binary = workDirectory.appending(path: "preflight-probe")
        let probe = """
            @_cdecl("LLVMFuzzerTestOneInput")
            public func probe(_ start: UnsafeRawPointer, _ count: Int) -> CInt { 0 }

            """
        guard (try? probe.write(to: source, atomically: true, encoding: .utf8)) != nil else {
            // If we cannot even stage the probe, do not block the build on it.
            return true
        }
        defer {
            try? FileManager.default.removeItem(at: source)
            try? FileManager.default.removeItem(at: binary)
        }

        var arguments = [
            source.path,
            "-sanitize=fuzzer",
            "-parse-as-library",
            "-o", binary.path,
        ]
        // Without an explicit SDK the probe fails to link with `library 'c++'
        // not found`, which would be a false negative on a perfectly good
        // toolchain. SwiftPM passes -sdk for real builds; the probe has to too.
        if let sdk = macOSSDKPath() {
            arguments += ["-sdk", sdk]
        }

        // Output is captured, never streamed: the whole point is that the user
        // sees our guidance instead of a raw driver or linker error.
        return (try? Process.status(swiftc, arguments)) == 0
    }

    private static func macOSSDKPath() -> String? {
        #if os(macOS)
        guard let path = try? Process.capture(URL(fileURLWithPath: "/usr/bin/xcrun"), ["--show-sdk-path"])
        else { return nil }
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
        #else
        return nil
        #endif
    }
}
