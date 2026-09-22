import Foundation

struct OSSFuzzError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

struct OSSFuzzConfiguration {
    static let defaultSwiftImage = "swift:6.3.3-noble@sha256:8de8ea332a61e961ead4ef41029c2552b18e1a70dd5942d25ecf7d8de2eec5b5"
    var repository: String?
    var output = "OSSFuzz"
    var contact = ""
    var swiftImage = defaultSwiftImage
    var includeCorpus = false
    var sanitizers = ["address"]

    static func parse(_ arguments: [String]) throws -> Self {
        var result = Self()
        var index = 0
        while index < arguments.count {
            let option = arguments[index]
            if option == "--include-corpus" {
                result.includeCorpus = true
            } else if option == "--help" || option == "-h" {
                throw OSSFuzzError(usage)
            } else {
                guard ["--repository", "--output", "--contact", "--swift-image", "--sanitizers"].contains(option) else {
                    throw OSSFuzzError("Unexpected argument \(String(reflecting: option)).\n\(usage)")
                }
                index += 1
                guard index < arguments.count, !arguments[index].hasPrefix("--") else { throw OSSFuzzError("\(option) requires a value.") }
                let value = arguments[index]
                switch option {
                case "--repository":
                    guard let normalized = OSSFuzzTemplates.normalizeRemote(value) else {
                        throw OSSFuzzError("--repository requires an anonymous HTTPS URL or an SSH remote convertible to HTTPS.")
                    }
                    result.repository = normalized
                case "--output": result.output = value
                case "--contact":
                    guard value.contains("@"), !value.contains(where: { $0.isWhitespace }) else { throw OSSFuzzError("--contact requires an email address.") }
                    result.contact = value
                case "--swift-image":
                    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./:_@-")
                    guard !value.isEmpty, value.unicodeScalars.allSatisfy(allowed.contains) else { throw OSSFuzzError("--swift-image requires a container image reference, preferably pinned by digest.") }
                    result.swiftImage = value
                case "--sanitizers":
                    let values = value.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
                    guard !values.isEmpty, values.allSatisfy({ ["address", "thread"].contains($0) }), Set(values).count == values.count else {
                        throw OSSFuzzError("Swift OSS-Fuzz sanitizers must be address, thread, or address,thread. Coverage is validated separately.")
                    }
                    result.sanitizers = values
                default: break
                }
            }
            index += 1
        }
        let components = result.output.split(separator: "/", omittingEmptySubsequences: false)
        guard !result.output.hasPrefix("/"), !components.isEmpty,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              !result.output.contains(where: { $0.isNewline || $0 == "\0" }) else {
            throw OSSFuzzError("--output must be a relative directory inside the fuzzing package, without '.' or '..' components.")
        }
        return result
    }

    static func relativePackagePath(package: URL, repositoryRoot: URL) throws -> String {
        let root = repositoryRoot.resolvingSymlinksInPath().standardizedFileURL.path
        let path = package.resolvingSymlinksInPath().standardizedFileURL.path
        if path == root { return "." }
        guard path.hasPrefix(root + "/") else { throw OSSFuzzError("The fuzzing package must be inside its Git repository.") }
        return String(path.dropFirst(root.count + 1))
    }

    static let usage = """
        USAGE: swift package --allow-writing-to-package-directory generate-oss-fuzz-script [options]

        Set up an OSS-Fuzz project with its own pinned Swift toolchain.
        Dockerfile, project.yaml and build.sh are preserved on regeneration.

        --repository <url>   Public repository to clone; defaults to Git origin.
        --output <dir>       Output inside the package (default: OSSFuzz).
        --contact <email>    Initial primary contact; may also be filled in project.yaml.
        --swift-image <ref>  Ubuntu 24.04 Swift image; default is pinned Swift 6.3.3.
                            Standalone targets need an explicitly pinned Swift 6.4 image.
        --sanitizers <list>  Initial sanitizers (default: address); thread is opt-in.
        --include-corpus     Include Corpus inputs as well as Seeds.
        """
}

enum OSSFuzzFiles {
    /// Preserve maintainer files, and refuse to overwrite edits to generated
    /// helpers. Validate all paths before writing any file.
    static func write(managed: [String: String], initial: [String: String], to directory: URL) throws -> [String] {
        let manager = FileManager.default
        let stateURL = directory.appending(path: ".swift-fuzz-generated.json")
        if (try? stateURL.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true {
            throw OSSFuzzError("Refusing to read generation state through symlink \(stateURL.path).")
        }
        let previous: [String: String]
        if manager.fileExists(atPath: stateURL.path) {
            previous = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: stateURL))
        } else { previous = [:] }
        for name in Array(managed.keys) + Array(initial.keys) + [stateURL.lastPathComponent] {
            let file = directory.appending(path: name)
            if (try? file.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true {
                throw OSSFuzzError("Refusing to overwrite symlink \(file.path).")
            }
            if let contents = managed[name], manager.fileExists(atPath: file.path) {
                let existing = try String(contentsOf: file, encoding: .utf8)
                guard existing == contents || existing == previous[name] else {
                    throw OSSFuzzError("Generated file \(file.path) was edited. Preserve those edits and use a new --output directory, or restore the generated file before retrying.")
                }
            }
        }
        if previous.isEmpty, manager.fileExists(atPath: directory.appending(path: "build.sh").path) {
            throw OSSFuzzError("An existing integration has no generation state. Use a new --output directory and migrate your customizations; existing files were preserved.")
        }
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        var preserved: [String] = []
        for (name, contents) in initial.sorted(by: { $0.key < $1.key }) {
            let file = directory.appending(path: name)
            if manager.fileExists(atPath: file.path) { preserved.append(name); continue }
            try contents.write(to: file, atomically: true, encoding: .utf8)
        }
        for (name, contents) in managed {
            try contents.write(to: directory.appending(path: name), atomically: true, encoding: .utf8)
        }
        try JSONEncoder().encode(managed).write(to: stateURL, options: .atomic)
        for name in ["build.sh", "validate.sh"] where manager.fileExists(atPath: directory.appending(path: name).path) {
            try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.appending(path: name).path)
        }
        return preserved
    }
}
