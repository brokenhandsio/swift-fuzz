import Foundation

/// Shrinking the corpus without losing coverage — or seeds.
enum Minimize {
    struct Result {
        let filesBefore: Int
        let bytesBefore: Int
        let filesAfter: Int
        let bytesAfter: Int
    }

    /// Reduces the corpus using the same observed features as normal fuzzing.
    /// Seeds are read-only. A successful merge may leave an empty working
    /// corpus when the seeds already contain all the necessary inputs.
    static func run(
        binary: URL, layout: Layout, symbolizer: URL?, passthrough: [String] = []
    ) throws -> Result {
        try InputReplacement.requireNoBackup(for: layout.corpus)
        let before = try measure(layout.corpus)
        guard before.files > 0 else {
            throw FuzzError("Corpus/\(layout.target) is empty; nothing to minimize.")
        }

        // User feature settings apply to both the merge and its verification.
        // The operation flags follow them so verification always replays and
        // the merge always writes to our staging directory.
        let arguments = FuzzerArguments.defaults(layout: layout) + passthrough
        let originalCoverage = try coverage(
            binary: binary, layout: layout, symbolizer: symbolizer,
            arguments: arguments, directories: layout.inputDirectories)

        let staging = try InputReplacement.stagingDirectory(for: layout.corpus)
        defer { try? FileManager.default.removeItem(at: staging) }
        var mergeArguments = arguments + ["-minimize_crash=0", "-merge=1", staging.path]
        if layout.hasSeeds { mergeArguments.append(layout.seeds.path) }
        mergeArguments.append(layout.corpus.path)

        let status = try Process.stream(
            binary, mergeArguments,
            environment: FuzzEnvironment.make(target: layout.target, symbolizer: symbolizer),
            currentDirectory: layout.packageDirectory)
        guard status == 0 else {
            throw FuzzError("libFuzzer's merge exited with status \(status); the corpus is unchanged.")
        }

        let seeds = try seedContents(layout: layout)
        for file in try regularFiles(in: staging) {
            if seeds.contains(try Data(contentsOf: file)) {
                try FileManager.default.removeItem(at: file)
            }
        }

        // Check the exact candidate we intend to install, including seeds that
        // remain outside it. Counts catch observed regressions, but cannot
        // prove equality of feature identities across nondeterministic runs.
        let candidateCoverage = try coverage(
            binary: binary, layout: layout, symbolizer: symbolizer,
            arguments: arguments,
            directories: layout.hasSeeds ? [staging.path, layout.seeds.path] : [staging.path])
        guard !Coverage.lostCoverage(before: originalCoverage, after: candidateCoverage) else {
            throw FuzzError("""
                Minimizing would lose observed coverage: \(originalCoverage) edges before, \(candidateCoverage) after.
                Corpus/\(layout.target) is unchanged.
                Check that the harness behaves deterministically for each input.
                """)
        }

        let after = try measure(staging)
        try InputReplacement.replace(layout.corpus, with: staging)
        return Result(filesBefore: before.files, bytesBefore: before.bytes,
                      filesAfter: after.files, bytesAfter: after.bytes)
    }

    /// Shrinks one crashing input in place.
    ///
    /// libFuzzer's `-minimize_crash` repeatedly re-runs progressively smaller
    /// mutations and keeps the smallest that still crashes, so the result is
    /// crashing by construction. It does not verify the crash is the *same*
    /// one, which is almost always true and occasionally not — if a minimized
    /// artefact stops looking like the bug you were chasing, the original is in
    /// version control.
    static func crash(
        binary: URL, layout: Layout, path: String, symbolizer: URL?,
        passthrough: [String]
    ) throws -> Result {
        let input = URL(fileURLWithPath: path, relativeTo: layout.packageDirectory)
        try InputReplacement.requireNoBackup(for: input)
        guard FileManager.default.fileExists(atPath: input.path) else {
            throw FuzzError("No such input: \(path)")
        }
        let before = (try Data(contentsOf: input)).count

        let directory = try InputReplacement.stagingDirectory(for: input)
        defer { try? FileManager.default.removeItem(at: directory) }
        let staging = directory.appending(path: "input")

        var arguments = FuzzerArguments.defaults(layout: layout)
        // Bounded so a stubborn input cannot run forever; overridable by passing
        // your own -runs=.
        if !passthrough.contains(where: { $0.hasPrefix("-runs=") }) {
            arguments.append("-runs=100000")
        }
        arguments += passthrough
        arguments += ["-minimize_crash=1", "-exact_artifact_path=\(staging.path)", input.path]

        let status = try Process.stream(
            binary, arguments,
            environment: FuzzEnvironment.make(target: layout.target, symbolizer: symbolizer),
            currentDirectory: layout.packageDirectory
        )

        guard FileManager.default.fileExists(atPath: staging.path) else {
            throw FuzzError("""
                No minimized input was produced for \(path) (exit \(status)); the original is unchanged.
                Check that the input reproduces with this target and review libFuzzer's output.
                """)
        }
        let after = (try Data(contentsOf: staging)).count

        guard after <= before else {
            throw FuzzError("Minimization produced a larger input; \(path) is unchanged.")
        }
        try InputReplacement.replace(input, with: staging)

        return Result(filesBefore: 1, bytesBefore: before, filesAfter: 1, bytesAfter: after)
    }

    private static func coverage(
        binary: URL, layout: Layout, symbolizer: URL?, arguments: [String], directories: [String]
    ) throws -> Int {
        let (status, diagnostics) = try Process.captureDiagnostics(
            binary, arguments + ["-merge=0", "-minimize_crash=0", "-runs=0"] + directories,
            environment: FuzzEnvironment.make(target: layout.target, symbolizer: symbolizer),
            currentDirectory: layout.packageDirectory)
        guard status == 0,
              let edges = Coverage.edgeCount(in: diagnostics) else {
            throw FuzzError("Could not verify corpus coverage (exit \(status)); Corpus/\(layout.target) is unchanged.")
        }
        return edges
    }

    private static func seedContents(layout: Layout) throws -> Set<Data> {
        guard layout.hasSeeds else { return [] }
        return try Set(regularFiles(in: layout.seeds).map { try Data(contentsOf: $0) })
    }

    private static func regularFiles(in directory: URL) throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: directory, includingPropertiesForKeys: [.isRegularFileKey]) else {
            throw FuzzError("Could not read inputs in \(directory.path).")
        }
        var files: [URL] = []
        for case let file as URL in enumerator {
            if try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
                files.append(file)
            }
        }
        return files
    }

    private static func measure(_ directory: URL) throws -> (files: Int, bytes: Int) {
        let files = try regularFiles(in: directory)
        let bytes = try files.reduce(0) { total, file in
            total + (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0)
        }
        return (files.count, bytes)
    }
}
