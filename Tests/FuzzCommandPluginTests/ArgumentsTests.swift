import Testing

// `Arguments.swift` in this directory is a symlink to the command plugin's copy,
// not a duplicate. SwiftPM forbids a plugin target from depending on a library
// target, so there is no module for tests to import; compiling the real file a
// second time is the only way to test it without letting a copy drift.
// Replacing the symlink with a copy would silently stop testing the shipped code.

@Suite("Argument parsing")
struct ArgumentsTests {
    // MARK: Target selection

    @Test("A bare word is the target name")
    func targetName() throws {
        #expect(try Arguments.parse(["MyTarget"]).target == "MyTarget")
    }

    @Test("No target is allowed; the plugin resolves a sole executable itself")
    func noTarget() throws {
        #expect(try Arguments.parse([]).target == nil)
    }

    @Test("A second bare word is an error rather than a silent override")
    func twoTargets() {
        #expect(throws: FuzzError.self) {
            try Arguments.parse(["One", "Two"])
        }
    }

    // MARK: Modes

    @Test("Default mode is fuzzing")
    func defaultMode() throws {
        guard case .fuzz = try Arguments.parse(["T"]).mode else {
            Issue.record("expected .fuzz")
            return
        }
    }

    @Test("--replay selects replay mode")
    func replayMode() throws {
        guard case .replay = try Arguments.parse(["T", "--replay"]).mode else {
            Issue.record("expected .replay")
            return
        }
    }

    @Test("--reproduce carries the path it was given")
    func reproduceMode() throws {
        guard case .reproduce(let path) = try Arguments.parse(["T", "--reproduce", "Crashes/T/x"]).mode else {
            Issue.record("expected .reproduce")
            return
        }
        #expect(path == "Crashes/T/x")
    }

    @Test("--reproduce without a path is an error, not a silent no-op")
    func reproduceNeedsPath() {
        #expect(throws: FuzzError.self) {
            try Arguments.parse(["T", "--reproduce"])
        }
    }

    @Test("--minimize-corpus selects minimize mode")
    func minimizeMode() throws {
        guard case .minimizeCorpus = try Arguments.parse(["T", "--minimize-corpus"]).mode else {
            Issue.record("expected .minimizeCorpus")
            return
        }
    }

    // MARK: Translated options

    @Test("--time becomes libFuzzer's -max_total_time")
    func timeTranslation() throws {
        #expect(try Arguments.parse(["T", "--time", "60"]).passthrough.contains("-max_total_time=60"))
    }

    @Test("--jobs becomes libFuzzer's -jobs")
    func jobsTranslation() throws {
        #expect(try Arguments.parse(["T", "--jobs", "4"]).passthrough.contains("-jobs=4"))
    }

    @Test("--time without a value is an error")
    func timeNeedsValue() {
        #expect(throws: FuzzError.self) {
            try Arguments.parse(["T", "--time"])
        }
    }

    // MARK: Build configuration

    @Test("Debug by default, release on request")
    func configuration() throws {
        #expect(try Arguments.parse(["T"]).release == false)
        #expect(try Arguments.parse(["T", "--release"]).release == true)
    }

    @Test("AddressSanitizer is on by default")
    func defaultSanitizers() throws {
        #expect(try Arguments.parse(["T"]).sanitizers == "fuzzer,address")
    }

    @Test("--no-asan drops to the fuzzer sanitizer alone")
    func noASan() throws {
        #expect(try Arguments.parse(["T", "--no-asan"]).sanitizers == "fuzzer")
    }

    @Test("--sanitizers overrides the set wholesale")
    func explicitSanitizers() throws {
        #expect(try Arguments.parse(["T", "--sanitizers", "fuzzer,undefined"]).sanitizers == "fuzzer,undefined")
    }

    // MARK: Passthrough

    @Test("Unrecognised -flags go to libFuzzer untouched")
    func passthrough() throws {
        let parsed = try Arguments.parse(["T", "-max_len=64", "-rss_limit_mb=4096", "-dict=x.dict"])
        #expect(parsed.passthrough == ["-max_len=64", "-rss_limit_mb=4096", "-dict=x.dict"])
        #expect(parsed.target == "T")
    }

    @Test("Passthrough keeps the order it was given")
    func passthroughOrder() throws {
        // The plugin appends its own defaults first and these afterwards, so a
        // user-supplied flag wins over the default. That only holds if order
        // survives parsing.
        let parsed = try Arguments.parse(["T", "-use_value_profile=0", "-max_len=8"])
        #expect(parsed.passthrough == ["-use_value_profile=0", "-max_len=8"])
    }

    @Test("A flag that looks like a target is still a flag")
    func flagsAreNotTargets() throws {
        let parsed = try Arguments.parse(["-runs=10"])
        #expect(parsed.target == nil)
        #expect(parsed.passthrough == ["-runs=10"])
    }

    @Test("Options may precede the target name")
    func optionsBeforeTarget() throws {
        let parsed = try Arguments.parse(["--time", "5", "MyTarget"])
        #expect(parsed.target == "MyTarget")
        #expect(parsed.passthrough.contains("-max_total_time=5"))
    }

    // MARK: Help

    @Test("--help throws, carrying the usage text as its message")
    func help() {
        #expect(throws: FuzzError.self) {
            try Arguments.parse(["--help"])
        }
        do {
            _ = try Arguments.parse(["--help"])
        } catch let error as FuzzError {
            #expect(error.description.contains("USAGE:"))
            #expect(error.description.contains("--replay"))
        } catch {
            Issue.record("expected FuzzError")
        }
    }
}
