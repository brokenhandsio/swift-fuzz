import Foundation

/// Shrinking the corpus without losing coverage — or seeds.
enum Minimize {
    struct Result {
        let filesBefore: Int
        let bytesBefore: Int
        let filesAfter: Int
        let bytesAfter: Int
    }

    /// Replaces the corpus with the smallest set of inputs that preserves its
    /// coverage.
    ///
    /// The merge runs over the seeds *and* the corpus together, then drops any
    /// result that is byte-identical to a seed. That yields a corpus holding
    /// only what the seeds do not already cover — minimizing the corpus alone
    /// would leave entries whose coverage a seed already provides.
    ///
    /// Seeds themselves are never written: they are an input to the merge and
    /// nothing more.
    static func run(binary: URL, layout: Layout, workDirectory: URL) throws -> Result {
        let before = try measure(layout.corpus)
        guard before.files > 0 else {
            throw FuzzError("Corpus/\(layout.target) is empty; nothing to minimize.")
        }

        let staging = workDirectory.appending(path: "minimize-\(layout.target)")
        try? FileManager.default.removeItem(at: staging)
        try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: staging) }

        // -merge=1 <dest> <sources...>: dest collects the minimal set.
        var arguments = ["-merge=1", staging.path]
        if layout.hasSeeds { arguments.append(layout.seeds.path) }
        arguments.append(layout.corpus.path)

        let status = try Process.stream(
            binary, arguments,
            environment: environment(for: layout),
            currentDirectory: layout.packageDirectory
        )
        guard status == 0 else {
            throw FuzzError("libFuzzer's merge exited with status \(status); the corpus is unchanged.")
        }

        let seedContents = try seedContents(layout: layout)
        var keep: [URL] = []
        for file in try FileManager.default.contentsOfDirectory(at: staging, includingPropertiesForKeys: nil) {
            let data = try Data(contentsOf: file)
            // Anything the seeds already carry belongs in Seeds/, not here.
            if seedContents.contains(data) { continue }
            keep.append(file)
        }

        // A merge that produced nothing almost certainly means the binary failed
        // rather than that the corpus was redundant. Refuse rather than delete.
        guard !keep.isEmpty else {
            throw FuzzError("""
                The merge produced no inputs, which should not happen for a non-empty corpus.
                Leaving Corpus/\(layout.target) untouched.
                """)
        }

        // Replace only once the new set is known-good.
        try FileManager.default.removeItem(at: layout.corpus)
        try FileManager.default.createDirectory(at: layout.corpus, withIntermediateDirectories: true)
        for file in keep {
            try FileManager.default.moveItem(at: file, to: layout.corpus.appending(path: file.lastPathComponent))
        }

        let after = try measure(layout.corpus)
        return Result(filesBefore: before.files, bytesBefore: before.bytes,
                      filesAfter: after.files, bytesAfter: after.bytes)
    }

    private static func seedContents(layout: Layout) throws -> Set<Data> {
        guard layout.hasSeeds else { return [] }
        let files = try FileManager.default.contentsOfDirectory(at: layout.seeds, includingPropertiesForKeys: nil)
        return Set(files.compactMap { try? Data(contentsOf: $0) })
    }

    private static func measure(_ directory: URL) throws -> (files: Int, bytes: Int) {
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: [.fileSizeKey])) ?? []
        let files = contents.filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
        let bytes = files.reduce(0) { $0 + ((try? $1.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0) }
        return (files.count, bytes)
    }

    private static func environment(for layout: Layout) -> [String: String] {
        var environment = ProcessInfo.processInfo.environment
        environment["FUZZ_TARGET"] = layout.target
        #if !os(macOS)
        environment["SWIFT_BACKTRACE"] = "enable=no"
        #endif
        return environment
    }
}
