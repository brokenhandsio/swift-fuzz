import Foundation

/// Locating libFuzzer's compiler-rt archive, and knowing when we have to link
/// it ourselves.
enum FuzzerRuntime {
    /// Finds `libclang_rt.fuzzer*.a` in the active toolchain.
    ///
    /// Two directory layouts are in the wild and `clang -print-runtime-dir`
    /// only knows about one of them: it reports the per-target directory
    /// (`lib/x86_64-unknown-linux-gnu`) even on toolchains that actually ship
    /// the archives in the legacy `lib/linux` / `lib/darwin` layout with an
    /// architecture suffix. So we check both.
    static func locateArchive(clang: URL) -> URL? {
        guard let runtimeDirectory = try? Process.capture(clang, ["-print-runtime-dir"])
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !runtimeDirectory.isEmpty
        else { return nil }

        let runtime = URL(fileURLWithPath: runtimeDirectory)
        let parent = runtime.deletingLastPathComponent()
        let architecture = machineArchitecture()

        #if os(macOS)
        let candidates = [
            runtime.appending(path: "libclang_rt.fuzzer_osx.a"),
            parent.appending(path: "darwin/libclang_rt.fuzzer_osx.a"),
        ]
        #else
        let candidates = [
            runtime.appending(path: "libclang_rt.fuzzer.a"),
            parent.appending(path: "linux/libclang_rt.fuzzer-\(architecture).a"),
        ]
        #endif

        return candidates.first { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// Linker flags that pull the whole archive in.
    ///
    /// Needed only on toolchains that do not forward `-sanitize=fuzzer` to the
    /// link step (Swift 6.3.x under the SwiftBuild backend). Applying them when
    /// the driver *has* already linked the archive is not harmless: Apple's ld
    /// silently deduplicates, but `ld.gold` fails the link with "multiple
    /// definition of 'fuzzer::...'". Hence ``needsExplicitLink(buildLog:)``.
    static func explicitLinkFlags(archive: URL) -> [String] {
        #if os(macOS)
        return ["-force_load", archive.path]
        #else
        // libFuzzer is C++, and on Linux nothing else on the link line drags in
        // the C++ runtime or these system libraries.
        return [
            "--whole-archive", archive.path, "--no-whole-archive",
            "-lstdc++", "-lm", "-lpthread", "-ldl", "-lrt",
        ]
        #endif
    }

    /// Whether a failed build failed *because* the fuzzer runtime was missing
    /// from the link line, as opposed to any other reason.
    static func needsExplicitLink(buildLog: String) -> Bool {
        buildLog.contains("sanitizer_cov") || buildLog.contains("__sancov_lowest_stack")
    }

    /// Whether a failed build failed because the toolchain has no libFuzzer at all.
    static func lacksFuzzerSupport(buildLog: String) -> Bool {
        buildLog.contains("unsupported option '-sanitize=fuzzer'")
            || buildLog.contains("libclang_rt.fuzzer")
    }

    static let missingToolchainMessage = """
        This toolchain does not include the libFuzzer runtime.

        libFuzzer ships inside the Swift toolchain as a compiler-rt archive and is
        ABI-coupled to the instrumentation your compiler emits, so it cannot be
        vendored or installed separately.

          macOS  The Swift toolchain bundled with Xcode does not include it. Install a
                 toolchain from swift.org (or `swiftly install 6.3.3`) and select it:

                     export TOOLCHAINS=org.swift.<identifier>
                     # or: xcrun --toolchain swift swift package fuzz ...

          Linux  Use the full `swift:6.3` Docker image or a swift.org tarball. The
                 `-slim` images have no compiler and will not work.
        """

    private static func machineArchitecture() -> String {
        #if arch(arm64)
        return "aarch64"
        #else
        return "x86_64"
        #endif
    }
}
