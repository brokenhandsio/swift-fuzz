/// Diagnostics for the two build failures whose raw output tells the user
/// nothing useful.
enum FuzzerRuntime {
    /// Whether a failed build failed because the toolchain has no libFuzzer at all.
    static func lacksFuzzerSupport(buildLog: String) -> Bool {
        buildLog.contains("unsupported option '-sanitize=fuzzer'")
            || buildLog.contains("libclang_rt.fuzzer")
    }

    /// Guidance for any other failed build.
    ///
    /// The overwhelmingly likely cause is an ordinary compile error in the
    /// harness, so that is named first; the backend caveat is named second
    /// because it is the one failure whose message is otherwise inscrutable.
    static let buildFailureMessage = """
        Build failed. See the compiler output above.

        If the errors are undefined `__sanitizer_cov_*` or `__asan_*` symbols, you are
        on Swift 6.3.x with `--build-system swiftbuild`, which forwards sanitizer flags
        to compilation but not to the link step. Drop the flag and use the default
        build system; swift-fuzz supports it on every toolchain it supports.
        """

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
}
