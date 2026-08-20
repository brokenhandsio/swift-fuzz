import Testing

// `OSSFuzzTemplates.swift` here is a symlink to the plugin's copy — see
// Tests/FuzzCommandPluginTests for why.

@Suite("OSS-Fuzz templates")
struct OSSFuzzTemplatesTests {
    @Test("The build script sources precompile_swift and uses its flags")
    func usesSwiftFlags() {
        let script = OSSFuzzTemplates.buildScript(packageDirectory: "Fuzzing", targets: ["A"])
        // OSS-Fuzz supplies the sanitizer and static-linking flags this way;
        // building without them produces a binary that will not run there.
        #expect(script.contains(". precompile_swift"))
        #expect(script.contains("swift build -c release $SWIFTFLAGS"))
    }

    @Test("Every target is built, copied, and given its corpus and dictionary")
    func packagesEachTarget() {
        let script = OSSFuzzTemplates.buildScript(packageDirectory: "Fuzzing", targets: ["A", "B"])
        #expect(script.contains("for target in A B"))
        #expect(script.contains(#"cp ".build/release/$target" "$OUT/$target""#))
        #expect(script.contains("_seed_corpus.zip"))
        #expect(script.contains(#""Dictionaries/$target.dict""#))
    }

    @Test("It cds into the fuzzing package, whatever it is called")
    func honoursPackageDirectory() {
        #expect(OSSFuzzTemplates.buildScript(packageDirectory: "FuzzTesting", targets: ["A"])
            .contains("cd FuzzTesting"))
    }

    @Test("Seeds and corpus are gathered without failing on an empty directory")
    func toleratesMissingDirectories() {
        // A glob over a missing or empty directory would either error under
        // `set -u` or pass a literal `*` to zip.
        let script = OSSFuzzTemplates.buildScript(packageDirectory: "Fuzzing", targets: ["A"])
        #expect(script.contains("find \"Seeds/$target\" \"Corpus/$target\" -type f"))
        #expect(!script.contains(#"zip -q -j "$OUT/${target}_seed_corpus.zip" "Seeds/$target"/*"#))
    }

    @Test("project.yaml declares Swift and only the supported sanitizers")
    func projectYAML() {
        let yaml = OSSFuzzTemplates.projectYAML(repository: "https://example.com/x")
        #expect(yaml.contains("language: swift"))
        #expect(yaml.contains("- address"))
        #expect(yaml.contains("- thread"))
        // OSS-Fuzz does not support UBSan for Swift; declaring it fails the build.
        #expect(!yaml.contains("- undefined"))
    }

    @Test("The Dockerfile starts from the Swift builder and clones the repo")
    func dockerfile() {
        let file = OSSFuzzTemplates.dockerfile(
            repository: "https://github.com/you/repo", checkoutName: "repo")
        #expect(file.contains("FROM gcr.io/oss-fuzz-base/base-builder-swift"))
        #expect(file.contains("git clone --depth 1 https://github.com/you/repo repo"))
        #expect(file.contains("WORKDIR $SRC/repo"))
    }

    @Test("SSH remotes become clonable https URLs", arguments: [
        ("git@github.com:brokenhandsio/swift-cbor.git", "https://github.com/brokenhandsio/swift-cbor"),
        ("git@github.com:brokenhandsio/swift-cbor", "https://github.com/brokenhandsio/swift-cbor"),
        ("ssh://git@github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("https://github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("https://github.com/owner/repo", "https://github.com/owner/repo"),
    ])
    func normalizesRemotes(remote: String, expected: String) {
        // OSS-Fuzz's builder clones anonymously, so an SSH remote — which is
        // what `git remote get-url` usually reports — cannot be used as-is.
        #expect(OSSFuzzTemplates.normalizeRemote(remote) == expected)
    }

    @Test("Unusable remotes are rejected rather than guessed at", arguments: [
        "", "   ", "/some/local/path", "file:///tmp/repo",
    ])
    func rejectsUnusableRemotes(remote: String) {
        #expect(OSSFuzzTemplates.normalizeRemote(remote) == nil)
    }

    @Test("The checkout directory drops any .git suffix", arguments: [
        ("https://github.com/owner/repo", "repo"),
        ("https://github.com/owner/repo.git", "repo"),
        ("https://github.com/owner/repo/", "repo"),
    ])
    func checkoutNames(repository: String, expected: String) {
        #expect(OSSFuzzTemplates.checkoutName(for: repository) == expected)
    }
}
