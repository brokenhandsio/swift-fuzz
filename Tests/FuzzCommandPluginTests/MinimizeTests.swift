import Foundation
import Testing

@Suite("Corpus minimization")
struct MinimizeTests {
    @Test("A corpus duplicated by seeds can become empty without changing the seeds")
    func redundantCorpus() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let result = try fixture.minimize()
        #expect(result.filesBefore == 1)
        #expect(result.filesAfter == 0)
        #expect(try Data(contentsOf: fixture.seed) == Data([1, 2, 3]))
        #expect(!FileManager.default.fileExists(atPath: InputReplacement.backup(for: fixture.layout.corpus).path))
    }

    @Test("Merge and verification use the same feature settings and honor overrides")
    func featureSettings() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        _ = try fixture.minimize(passthrough: ["-use_value_profile=0", "-max_len=128"])
        let calls = try String(contentsOf: fixture.root.appending(path: "arguments"), encoding: .utf8)
            .split(separator: "\n")
        #expect(calls.count == 3)
        for call in calls {
            #expect(call.contains("-detect_leaks=0"))
            #expect(call.contains("-use_value_profile=1 -use_value_profile=0 -max_len=128"))
        }
    }

    @Test("Failed or incomplete measurements leave the original corpus intact", arguments: [
        "exit 1", "echo no-counters >&2", "echo '#2 DONE ft: 20' >&2",
    ])
    func failedMeasurement(diagnostics: String) throws {
        let fixture = try Fixture(candidate: diagnostics)
        defer { fixture.remove() }
        #expect(throws: (any Error).self) { try fixture.minimize() }
        #expect(try Data(contentsOf: fixture.corpusInput) == Data([1, 2, 3]))
    }

    @Test("An observed edge loss refuses replacement")
    func lostEdges() throws {
        let fixture = try Fixture(candidate: "echo '#2 DONE cov: 9 ft: 20' >&2")
        defer { fixture.remove() }
        #expect(throws: (any Error).self) { try fixture.minimize() }
        #expect(try Data(contentsOf: fixture.corpusInput) == Data([1, 2, 3]))
    }

    @Test("Value-profile count variation does not reject a corpus duplicated by seeds")
    func varyingFeatureCounts() throws {
        let fixture = try Fixture(candidate: "echo '#2 DONE cov: 10 ft: 19' >&2")
        defer { fixture.remove() }
        #expect(try fixture.minimize().filesAfter == 0)
    }

    @Test("A failed merge leaves the original corpus intact")
    func failedMerge() throws {
        let fixture = try Fixture(mergeStatus: 1)
        defer { fixture.remove() }
        #expect(throws: (any Error).self) { try fixture.minimize() }
        #expect(try Data(contentsOf: fixture.corpusInput) == Data([1, 2, 3]))
    }

    /// A process fixture simulates engine results without depending on an
    /// installed libFuzzer runtime. Real merging is also exercised in CI.
    private struct Fixture {
        let root: URL
        let layout: Layout
        let binary: URL
        let seed: URL
        let corpusInput: URL

        init(candidate: String = "echo '#2 DONE cov: 10 ft: 20' >&2", mergeStatus: Int = 0) throws {
            root = FileManager.default.temporaryDirectory.appending(path: "minimize-test-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            layout = try Layout(packageDirectory: root, target: "Probe")
            try layout.create()
            try FileManager.default.createDirectory(at: layout.seeds, withIntermediateDirectories: true)
            seed = layout.seeds.appending(path: "seed")
            corpusInput = layout.corpus.appending(path: "original")
            try Data([1, 2, 3]).write(to: seed)
            try Data([1, 2, 3]).write(to: corpusInput)
            binary = root.appending(path: "engine")
            // Keep the executable immutable while concurrent tests spawn it;
            // executing freshly written scripts can fail with ETXTBSY on Linux.
            let script = try #require(Bundle.module.url(forResource: "minimize", withExtension: "sh", subdirectory: "Fixtures"))
            try FileManager.default.createSymbolicLink(at: binary, withDestinationURL: script)
            try candidate.write(to: root.appending(path: "candidate.sh"), atomically: true, encoding: .utf8)
            try String(mergeStatus).write(to: root.appending(path: "merge-status"), atomically: true, encoding: .utf8)
        }

        func minimize(passthrough: [String] = []) throws -> Minimize.Result {
            try Minimize.run(binary: binary, layout: layout, symbolizer: nil, passthrough: passthrough)
        }

        func remove() { try? FileManager.default.removeItem(at: root) }
    }
}

@Suite("Input replacement")
struct InputReplacementTests {
    private enum Failure: Error { case simulated }

    @Test("Failed installation restores the original directory")
    func restoresOriginal() throws {
        try withInputs { (original: URL, staged: URL) throws -> Void in
            #expect(throws: (any Error).self) {
                try InputReplacement.replace(original, with: staged, move: { from, to in
                    if from == staged { throw Failure.simulated }
                    try FileManager.default.moveItem(at: from, to: to)
                })
            }
            #expect(try Data(contentsOf: original.appending(path: "input")) == Data([1]))
            #expect(try Data(contentsOf: staged.appending(path: "input")) == Data([2]))
        }
    }

    @Test("Failed restoration retains a recoverable backup")
    func retainsBackup() throws {
        try withInputs { (original: URL, staged: URL) throws -> Void in
            #expect(throws: (any Error).self) {
                try InputReplacement.replace(original, with: staged, move: { from, to in
                    if from != original { throw Failure.simulated }
                    try FileManager.default.moveItem(at: from, to: to)
                })
            }
            #expect(try Data(contentsOf: InputReplacement.backup(for: original).appending(path: "input")) == Data([1]))
        }
    }

    @Test("An existing backup is never overwritten")
    func existingBackup() throws {
        try withInputs { (original: URL, staged: URL) throws -> Void in
            let backup = InputReplacement.backup(for: original)
            try FileManager.default.copyItem(at: original, to: backup)
            #expect(throws: (any Error).self) { try InputReplacement.replace(original, with: staged) }
            #expect(try Data(contentsOf: original.appending(path: "input")) == Data([1]))
            #expect(try Data(contentsOf: backup.appending(path: "input")) == Data([1]))
        }
    }

    @Test("File replacement installs the candidate before removing the original backup")
    func replacesFile() throws {
        try withInputs { (original: URL, staged: URL) throws -> Void in
            let input = original.appending(path: "input")
            let candidate = staged.appending(path: "input")
            try InputReplacement.replace(input, with: candidate, remove: { backup in
                #expect(try Data(contentsOf: input) == Data([2]))
                #expect(try Data(contentsOf: backup) == Data([1]))
                try FileManager.default.removeItem(at: backup)
            })
            #expect(try Data(contentsOf: input) == Data([2]))
        }
    }

    private func withInputs(_ body: (URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "replacement-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let original = root.appending(path: "Corpus")
        let staged = root.appending(path: "Staged")
        for (directory, byte) in [(original, UInt8(1)), (staged, UInt8(2))] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try Data([byte]).write(to: directory.appending(path: "input"))
        }
        try body(original, staged)
    }
}
