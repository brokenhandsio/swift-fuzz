import Foundation

/// Where a target's seeds, corpus, crashes and dictionary live.
struct Layout {
    let packageDirectory: URL
    let target: String

    /// Hand-written starting inputs. libFuzzer is given this directory *after*
    /// the corpus, which makes it read-only: new discoveries go to the first
    /// directory on the command line and never here.
    ///
    /// The separation is what keeps curated inputs safe from `-merge=1`, which
    /// rewrites the directory it minimizes and would otherwise delete any seed
    /// whose coverage is reachable some other way. Specification vectors are
    /// documentation as much as coverage; losing them loses the provenance.
    let seeds: URL

    /// The working corpus: libFuzzer's accumulated discoveries. Written to.
    let corpus: URL
    let crashes: URL
    let dictionary: URL?

    init(packageDirectory: URL, target: String) throws {
        self.packageDirectory = packageDirectory
        self.target = target
        self.seeds = packageDirectory.appending(path: "Seeds/\(target)")
        self.corpus = packageDirectory.appending(path: "Corpus/\(target)")
        self.crashes = packageDirectory.appending(path: "Crashes/\(target)")
        let dictionary = packageDirectory.appending(path: "Dictionaries/\(target).dict")
        self.dictionary = FileManager.default.fileExists(atPath: dictionary.path) ? dictionary : nil
    }

    func create() throws {
        // Seeds are deliberately not created: an empty directory would be noise
        // in every package that does not curate any.
        for directory in [corpus, crashes] {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    /// Directories holding inputs to read, in the order libFuzzer should see
    /// them: the writable corpus first, then any read-only seeds.
    var inputDirectories: [String] {
        var directories = [corpus.path]
        if hasSeeds { directories.append(seeds.path) }
        return directories
    }

    /// Whether any seed inputs are present. An empty or missing directory is
    /// not passed, because libFuzzer treats a directory it cannot read as an
    /// error rather than as "no inputs".
    var hasSeeds: Bool {
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: seeds.path)) ?? []
        return !contents.isEmpty
    }

    /// Whether any crashing inputs have been saved for this target.
    var hasCrashArtefacts: Bool {
        !crashArtefacts().isEmpty
    }

    /// Crash artefacts, oldest first.
    func crashArtefacts() -> [URL] {
        let contents = (try? FileManager.default.contentsOfDirectory(
            at: crashes,
            includingPropertiesForKeys: [.contentModificationDateKey]
        )) ?? []
        return contents.sorted {
            let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return left < right
        }
    }
}
