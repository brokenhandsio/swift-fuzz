import Foundation
import Testing

@Suite("Target discovery")
struct DiscoveryTests {
    private func withDiscovery(
        _ outputs: [(String, String)], failing: String? = nil,
        _ body: (Discovery) throws -> Void
    ) throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let script = try #require(Bundle.module.url(forResource: "discover", withExtension: "sh", subdirectory: "Fixtures"))
        for (product, output) in outputs {
            let binary = directory.appending(path: product)
            try FileManager.default.createSymbolicLink(at: binary, withDestinationURL: script)
            try output.write(to: directory.appending(path: product + ".stdout"), atomically: true, encoding: .utf8)
            try (product == failing ? "1" : "0").write(to: directory.appending(path: product + ".status"), atomically: true, encoding: .utf8)
        }
        try body(Discovery(products: outputs.map(\.0), build: { directory.appending(path: $0) }))
    }

    @Test("Product-name resolution cannot bypass package-wide collisions")
    func productShortcut() throws {
        try withDiscovery([("Parser", "Parser\n"), ("Other", "parser\n")]) { discovery in
            #expect(throws: FuzzError.self) { try discovery.resolve(requested: "Parser") }
            #expect(throws: FuzzError.self) { try discovery.all() }
        }
    }

    @Test("A logical name wins over another product's alias")
    func logicalBeforeAlias() throws {
        try withDiscovery([("Parser", "Different\n"), ("Other", "Parser\n")]) { discovery in
            let result = try discovery.resolve(requested: "Parser")
            #expect(result.binary.lastPathComponent == "Other")
            #expect(result.target == "Parser")
        }
    }

    @Test("Product aliases still select a sole target")
    func alias() throws {
        try withDiscovery([("Product", "Logical\n"), ("Other", "Elsewhere\n")]) { discovery in
            let result = try discovery.resolve(requested: "Product")
            #expect(result.target == "Logical")
        }
    }

    @Test("Malformed, duplicate and empty discovery output is rejected", arguments: [
        "../escape\n", " LeadingSpace\n", "A\nA\n", "",
    ])
    func malformed(_ output: String) throws {
        try withDiscovery([("Product", output)]) { discovery in
            #expect(throws: FuzzError.self) { try discovery.resolve(requested: "Product") }
        }
    }

    @Test("A failed discovery cannot masquerade as successful target output")
    func failedProcess() throws {
        try withDiscovery([("Product", "Valid\n")], failing: "Product") { discovery in
            #expect(throws: FuzzError.self) { try discovery.all() }
        }
    }

    @Test("Absent and ambiguous selection retain useful errors")
    func missingSelection() throws {
        try withDiscovery([("Product", "First\nSecond\n")]) { discovery in
            #expect(throws: FuzzError.self) { try discovery.resolve(requested: nil) }
            #expect(throws: FuzzError.self) { try discovery.resolve(requested: "Product") }
            let result = try discovery.resolve(requested: "Second")
            #expect(result.target == "Second")
        }
    }
}
