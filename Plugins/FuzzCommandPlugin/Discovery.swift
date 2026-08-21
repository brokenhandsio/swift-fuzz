import Foundation
import PackagePlugin

/// Works out which executable to build and which fuzz target inside it to run.
///
/// A fuzz target's name lives in a closure in the user's source, so nothing
/// outside the process can know it. Rather than parse Swift or make people
/// repeat the names in `Package.swift`, the built executable is asked: with
/// `FUZZ_LIST_TARGETS` set it prints what it registered and exits. The registry
/// stays the single source of truth, and a rename cannot leave the two out of
/// step.
struct Discovery {
    /// One executable product and the fuzz targets it registers.
    struct Executable {
        let product: String
        let binary: URL
        let targets: [String]
    }

    /// The product to build, and the target within it to run.
    struct Resolution {
        let binary: URL
        let target: String
    }

    let context: PluginContext
    /// Builds a product and returns its executable.
    let build: (String) throws -> URL

    private var products: [String] {
        context.package.products.compactMap { $0 as? ExecutableProduct }.map(\.name)
    }

    /// Builds `product` and asks it what it registers.
    func inspect(_ product: String) throws -> Executable {
        let binary = try build(product)
        // No target and no symbolizer: this only asks the binary what it
        // registers, and exits before running anything.
        let environment = FuzzEnvironment.make(target: nil, symbolizer: nil, listTargets: true)
        let output = try Process.captureOutput(binary, [], environment: environment) ?? ""
        let targets = output
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return Executable(product: product, binary: binary, targets: targets)
    }

    /// Every fuzz target in the package. Builds each executable, so it is only
    /// used for `--list` and for error messages.
    func all() throws -> [Executable] {
        try products.map { try inspect($0) }
    }

    func resolve(requested: String?) throws -> Resolution {
        guard !products.isEmpty else {
            throw FuzzError("""
                This package declares no fuzz targets.
                Add one with: swift package fuzz-init <Name>
                """)
        }

        // Fast path: the name is a product. Covers one-target-per-executable,
        // which is the common layout, and avoids building anything else.
        if let requested, products.contains(requested) {
            let executable = try inspect(requested)
            if executable.targets.contains(requested) {
                return Resolution(binary: executable.binary, target: requested)
            }
            // A product whose single target is named differently: unambiguous,
            // so run it rather than being pedantic about the mismatch.
            if executable.targets.count == 1 {
                return Resolution(binary: executable.binary, target: executable.targets[0])
            }
            throw FuzzError("""
                "\(requested)" builds, but registers \(executable.targets.count) fuzz targets and \
                none is called "\(requested)".
                Pick one: \(executable.targets.joined(separator: ", "))
                """)
        }

        // Otherwise the name (or the absence of one) has to be matched against
        // what the executables actually register, which means building them.
        let executables = try all()
        let everything = executables.flatMap { executable in
            executable.targets.map { (product: executable.product, target: $0, binary: executable.binary) }
        }

        guard let requested else {
            if everything.count == 1 {
                return Resolution(binary: everything[0].binary, target: everything[0].target)
            }
            throw FuzzError("""
                This package has \(everything.count) fuzz targets; name the one you want.
                \(listing(executables))
                """)
        }

        let matches = everything.filter { $0.target == requested }
        if matches.count == 1 {
            return Resolution(binary: matches[0].binary, target: matches[0].target)
        }
        if matches.count > 1 {
            throw FuzzError("""
                "\(requested)" is registered by more than one executable \
                (\(matches.map(\.product).joined(separator: ", "))). Fuzz target names must be \
                unique across the package.
                """)
        }
        throw FuzzError("""
            No fuzz target named "\(requested)".
            \(listing(executables))
            """)
    }

    func listing(_ executables: [Executable]) -> String {
        executables.map { executable in
            let targets = executable.targets.isEmpty
                ? "  (registers none)"
                : executable.targets.map { "  \($0)" }.joined(separator: "\n")
            return "\(executable.product):\n\(targets)"
        }.joined(separator: "\n")
    }
}
