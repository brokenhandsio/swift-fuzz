import Foundation

/// Installs staged inputs while retaining a recoverable original.
enum InputReplacement {
    static func stagingDirectory(for original: URL) throws -> URL {
        // A sibling stays on the same filesystem, so installing the staged
        // directory is a rename rather than a series of copies.
        let directory = original.deletingLastPathComponent()
            .appending(path: ".\(original.lastPathComponent).minimize-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }

    static func backup(for original: URL) -> URL {
        original.deletingLastPathComponent()
            .appending(path: ".\(original.lastPathComponent).swift-fuzz-backup")
    }

    static func requireNoBackup(for original: URL) throws {
        let backup = backup(for: original)
        guard !FileManager.default.fileExists(atPath: backup.path) else {
            throw FuzzError("A previous input backup exists at \(backup.path). Recover or remove it before minimizing again.")
        }
    }

    static func replace(
        _ original: URL, with staged: URL,
        move: (URL, URL) throws -> Void = { try FileManager.default.moveItem(at: $0, to: $1) },
        remove: (URL) throws -> Void = { try FileManager.default.removeItem(at: $0) }
    ) throws {
        let backup = backup(for: original)
        try requireNoBackup(for: original)
        try move(original, backup)
        do {
            try move(staged, original)
        } catch {
            let installError = error
            do {
                try move(backup, original)
            } catch {
                throw FuzzError("Could not install minimized inputs or restore their original path. Original inputs remain at \(backup.path). Installation failed: \(installError); restoration failed: \(error)")
            }
            throw FuzzError("Could not install minimized inputs; the original was restored. \(installError)")
        }
        do {
            try remove(backup)
        } catch {
            throw FuzzError("Minimized inputs were installed, but the original backup could not be removed: \(backup.path). \(error)")
        }
    }
}
