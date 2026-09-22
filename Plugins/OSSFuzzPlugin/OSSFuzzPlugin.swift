import Foundation
import PackagePlugin

@main
struct OSSFuzzPlugin: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        if arguments == ["--help"] || arguments == ["-h"] {
            print(OSSFuzzConfiguration.usage)
            return
        }
        let options = try OSSFuzzConfiguration.parse(arguments)
        let package = context.package.directoryURL
        let products = context.package.products.compactMap { $0 as? ExecutableProduct }.map(\.name).sorted()
        guard !products.isEmpty else { throw OSSFuzzError("This package declares no executable fuzz products. Add one with swift package fuzz-init <Name>.") }
        guard let root = try git(["rev-parse", "--show-toplevel"], in: package) else {
            throw OSSFuzzError("Run this command inside a Git repository so the package's repository-relative path can be determined.")
        }
        let relativePath = try OSSFuzzConfiguration.relativePackagePath(package: package, repositoryRoot: URL(fileURLWithPath: root))
        let detected = try git(["remote", "get-url", "origin"], in: package).flatMap(OSSFuzzTemplates.normalizeRemote)
        guard let repository = options.repository ?? detected else {
            throw OSSFuzzError("No public repository could be determined. Pass --repository https://github.com/owner/repo.")
        }
        let checkout = try OSSFuzzTemplates.checkoutName(for: repository)
        let output = package.appending(path: options.output)
        let resolvedOutput = output.resolvingSymlinksInPath().standardizedFileURL.path
        guard resolvedOutput.hasPrefix(package.resolvingSymlinksInPath().standardizedFileURL.path + "/") else {
            throw OSSFuzzError("The output must remain inside the fuzzing package, including through symlinks.")
        }
        let configuration: [String: Any] = [
            "version": 1, "checkout": checkout, "package": relativePath, "products": products,
            "include_corpus": options.includeCorpus, "exclude_targets": options.excludedTargets,
        ]
        let json = try JSONSerialization.data(withJSONObject: configuration, options: [.prettyPrinted, .sortedKeys])
        let preserved = try OSSFuzzFiles.write(managed: [
            "swift-fuzz-config.json": String(decoding: json, as: UTF8.self) + "\n",
            "swift-fuzz-build.py": OSSFuzzTemplates.exporter,
            "validate.sh": OSSFuzzTemplates.validationScript,
            "README.md": OSSFuzzTemplates.readme,
        ], initial: [
            "Dockerfile": OSSFuzzTemplates.dockerfile(repository: repository, checkout: checkout, swiftImage: options.swiftImage),
            "project.yaml": OSSFuzzTemplates.projectYAML(repository: repository, contact: options.contact, sanitizers: options.sanitizers),
            "build.sh": OSSFuzzTemplates.buildScript,
        ], to: output)
        print("""
            Wrote OSS-Fuzz setup to \(options.output)/ for \(products.count) executable product(s).
            Logical fuzz targets will be discovered and exported during the OSS-Fuzz build.
            Excluded logical targets: \(options.excludedTargets.isEmpty ? "none" : options.excludedTargets.joined(separator: ", "))
            Repository: \(repository)
            Package: \(relativePath)
            Swift toolchain: see \(options.output)/Dockerfile.
            \(preserved.isEmpty ? "Customize Dockerfile, project.yaml and build.sh as needed." : "Preserved your existing " + preserved.joined(separator: ", ") + ". New contact, sanitizer and Swift image options only initialize missing files.")
            See \(options.output)/README.md and run validate.sh from your OSS-Fuzz checkout before submitting.
            """)
    }

    private func git(_ arguments: [String], in directory: URL) throws -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git", "-C", directory.path] + arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
