import Foundation

/// Turning `$s12BuggyLibraryAAO10parseAsyncyySays5UInt8VGYaKFZ` back into
/// `static BuggyLibrary.parseAsync([Swift.UInt8]) async throws -> ()`.
///
/// Only Linux needs this. macOS symbolizes through a tool that understands
/// Swift's mangling, so its reports arrive readable; llvm-symbolizer on Linux
/// leaves Swift symbols exactly as the linker wrote them.
enum Demangle {
    /// Demangles every mangled name in `names`, returning a lookup from the
    /// original.
    ///
    /// One process handles the whole batch: `swift-demangle` reads one symbol
    /// per line and echoes anything it does not recognise unchanged, so a
    /// thousand functions cost a single spawn.
    ///
    /// Any failure returns an empty mapping rather than throwing. A report with
    /// mangled names is worse than one without, but it is still a report, and
    /// there is nothing the user could do about a missing tool anyway.
    static func names(
        _ names: some Collection<String>, using tool: URL?, workDirectory: URL
    ) -> [String: String] {
        let mangled = Set(names.filter(Coverage.isMangled))
        guard let tool, !mangled.isEmpty else { return [:] }

        let ordered = Array(mangled)
        // stdin comes from a file rather than a pipe: writing a large batch
        // into a pipe while the child is still writing its own output can
        // deadlock, and this side-steps it entirely.
        let input = workDirectory.appending(path: "demangle-input.txt")
        defer { try? FileManager.default.removeItem(at: input) }

        do {
            try ordered.joined(separator: "\n").write(to: input, atomically: true, encoding: .utf8)

            let process = Process()
            process.executableURL = tool
            process.arguments = ["--compact"]
            process.standardInput = try FileHandle(forReadingFrom: input)
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return [:] }

            let output = String(decoding: data, as: UTF8.self)
                .split(separator: "\n", omittingEmptySubsequences: false)
                .filter { !$0.isEmpty }
            // A line-for-line correspondence is the only thing that makes the
            // result meaningful. If it does not hold, something changed about
            // the tool and guessing would mislabel functions.
            guard output.count == ordered.count else { return [:] }

            return Dictionary(uniqueKeysWithValues: zip(ordered, output.map(String.init)))
        } catch {
            return [:]
        }
    }
}
