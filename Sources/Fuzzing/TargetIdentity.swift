/// Names are also corpus directories and exported executable filenames.
/// Shared with the command plugin so discovery cannot reinterpret a name.
enum TargetIdentity {
    static func validationError(_ names: [String]) -> String? {
        var seen: [String: String] = [:]
        for name in names {
            let bytes = Array(name.utf8)
            func letter(_ byte: UInt8) -> Bool {
                (65...90).contains(byte) || (97...122).contains(byte)
            }
            guard let first = bytes.first, letter(first) || first == 95,
                  bytes.count <= 128,
                  bytes.allSatisfy({ letter($0) || (48...57).contains($0) || $0 == 95 || $0 == 45 })
            else {
                return """
                    Invalid fuzz target name \(String(reflecting: name)). Use an ASCII letter or \
                    underscore first, then ASCII letters, digits, underscores or hyphens (maximum 128 bytes).
                    """
            }
            let key = name.lowercased()
            if key == "llvm-symbolizer" || key == "llvm-symbolizer-swift" {
                return "Fuzz target name \(String(reflecting: name)) is reserved for the symbolizer."
            }
            if let previous = seen[key] {
                return """
                    Duplicate fuzz target names \(String(reflecting: previous)) and \(String(reflecting: name)). \
                    Names must be unique across the package, ignoring ASCII case, so their input directories \
                    and exported files cannot collide.
                    """
            }
            seen[key] = name
        }
        return nil
    }
}
