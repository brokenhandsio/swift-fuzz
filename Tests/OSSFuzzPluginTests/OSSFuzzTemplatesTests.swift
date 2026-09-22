import Foundation
import Testing

@Suite("OSS-Fuzz setup")
struct OSSFuzzTemplatesTests {
    @Test("SSH and HTTPS repositories normalize identically", arguments: [
        "git@github.com:owner/repo.git", "ssh://git@github.com/owner/repo.git", "https://github.com/owner/repo.git", "https://github.com/owner/repo/",
    ])
    func remotes(_ remote: String) throws {
        #expect(OSSFuzzTemplates.normalizeRemote(remote) == "https://github.com/owner/repo")
        let options = try OSSFuzzConfiguration.parse(["--repository", remote])
        #expect(options.repository == "https://github.com/owner/repo")
    }

    @Test("Unusable or credentialed repository values are rejected", arguments: [
        "", "/tmp/repo", "file:///tmp/repo", "https://", "https://example.com/", "https://user:secret@example.com/repo",
        "http://example.com/repo", "https://example.com/repo?token=x", "https://example.com/repo\nRUN bad", "ssh://git@example.com:2222/repo",
    ])
    func invalidRemote(_ remote: String) {
        #expect(OSSFuzzTemplates.normalizeRemote(remote) == nil)
    }

    @Test("Defaults support seeds-only builds independently of upstream Swift")
    func defaults() throws {
        let options = try OSSFuzzConfiguration.parse([])
        #expect(!options.includeCorpus)
        #expect(options.sanitizers == ["address"])
        #expect(options.excludedTargets.isEmpty)
        #expect(options.swiftImage.contains("6.3.3-noble@sha256:"))
        let docker = OSSFuzzTemplates.dockerfile(repository: "https://example.com/repo", checkout: "repo", swiftImage: options.swiftImage)
        #expect(docker.contains("COPY --from=swift-toolchain /usr /opt/swift/usr"))
        #expect(docker.contains("WORKDIR /src/repo"))
        #expect(docker.contains("base-builder-swift:ubuntu-24-04"))
        #expect(OSSFuzzTemplates.buildScript.contains(". precompile_swift"))
    }

    @Test("Custom configuration remains explicit")
    func customOptions() throws {
        let options = try OSSFuzzConfiguration.parse(["--include-corpus", "--swift-image", "swiftlang/swift:6.4-pinned-noble", "--contact", "owner@example.com", "--sanitizers", "address,thread", "--exclude-target", "KnownCrash", "--exclude-target", "Other-Crash"])
        #expect(options.includeCorpus)
        #expect(options.swiftImage == "swiftlang/swift:6.4-pinned-noble")
        #expect(options.contact == "owner@example.com")
        #expect(options.sanitizers == ["address", "thread"])
        #expect(options.excludedTargets == ["KnownCrash", "Other-Crash"])
        let yaml = OSSFuzzTemplates.projectYAML(repository: "https://example.com/repo", contact: options.contact, sanitizers: options.sanitizers)
        #expect(yaml.contains("primary_contact: \"owner@example.com\""))
        #expect(yaml.contains("base_os_version: ubuntu-24-04"))
        #expect(yaml.contains("- x86_64"))
        #expect(yaml.contains("- thread"))
    }

    @Test("Invalid options fail before generation", arguments: [
        ["--output", "../escape"], ["--output", "/tmp/out"], ["--output", "."], ["--output", "a//b"],
        ["--swift-image", "image\nRUN bad"], ["--sanitizers", "undefined"], ["--sanitizers", "address,"],
        ["--exclude-target", "../escape"], ["--exclude-target", "llvm-symbolizer"],
        ["--exclude-target", "Same", "--exclude-target", "same"],
        ["--contact", "invalid"], ["--repository"], ["--unknown"],
    ])
    func badOptions(_ arguments: [String]) {
        #expect(throws: OSSFuzzError.self) { try OSSFuzzConfiguration.parse(arguments) }
    }

    @Test("Root and deeply nested package locations are repository-relative")
    func paths() throws {
        let root = URL(fileURLWithPath: "/tmp/swift-fuzz-path-root")
        let atRoot = try OSSFuzzConfiguration.relativePackagePath(package: root, repositoryRoot: root)
        let nested = try OSSFuzzConfiguration.relativePackagePath(package: root.appending(path: "Tests/With Space/Fuzzing"), repositoryRoot: root)
        #expect(atRoot == ".")
        #expect(nested == "Tests/With Space/Fuzzing")
        #expect(throws: OSSFuzzError.self) {
            try OSSFuzzConfiguration.relativePackagePath(package: URL(fileURLWithPath: "/tmp/swift-fuzz-path-root-other"), repositoryRoot: root)
        }
    }

    @Test("Regeneration preserves configuration and detects edits to generated helpers")
    func regeneration() throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        _ = try OSSFuzzFiles.write(managed: ["helper.py": "original"], initial: ["project.yaml": "contact: first"], to: directory)
        let yaml = directory.appending(path: "project.yaml")
        try "contact: customized".write(to: yaml, atomically: true, encoding: .utf8)
        let preserved = try OSSFuzzFiles.write(managed: ["helper.py": "updated"], initial: ["project.yaml": "contact: replacement"], to: directory)
        #expect(preserved == ["project.yaml"])
        let contents = try String(contentsOf: yaml, encoding: .utf8)
        #expect(contents == "contact: customized")
        let helper = directory.appending(path: "helper.py")
        try "custom helper".write(to: helper, atomically: true, encoding: .utf8)
        #expect(throws: OSSFuzzError.self) {
            try OSSFuzzFiles.write(managed: ["helper.py": "next", "another": "new"], initial: [:], to: directory)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appending(path: "another").path))
        let retained = try String(contentsOf: helper, encoding: .utf8)
        #expect(retained == "custom helper")
    }

    @Test("Legacy integrations and symlinks are preserved on refusal")
    func unsafeRegeneration() throws {
        let manager = FileManager.default
        let directory = manager.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? manager.removeItem(at: directory) }
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        let build = directory.appending(path: "build.sh")
        try "custom legacy build".write(to: build, atomically: true, encoding: .utf8)
        #expect(throws: OSSFuzzError.self) {
            try OSSFuzzFiles.write(managed: ["helper.py": "new"], initial: ["build.sh": "new"], to: directory)
        }
        #expect(!manager.fileExists(atPath: directory.appending(path: "helper.py").path))
        let original = try String(contentsOf: build, encoding: .utf8)
        #expect(original == "custom legacy build")
        try manager.removeItem(at: build)
        let outside = directory.appending(path: "maintainer.txt")
        try "keep".write(to: outside, atomically: true, encoding: .utf8)
        try manager.createSymbolicLink(at: directory.appending(path: "helper.py"), withDestinationURL: outside)
        #expect(throws: OSSFuzzError.self) {
            try OSSFuzzFiles.write(managed: ["helper.py": "new"], initial: [:], to: directory)
        }
        let retained = try String(contentsOf: outside, encoding: .utf8)
        #expect(retained == "keep")
    }
}
