import Foundation

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

    let products: [String]
    /// Builds a product and returns its executable.
    let build: (String) throws -> URL

    /// Builds `product` and asks it what it registers.
    func inspect(_ product: String) throws -> Executable {
        let binary = try build(product)
        // No target and no symbolizer: this only asks the binary what it
        // registers, and exits before running anything.
        let environment = FuzzEnvironment.make(target: nil, symbolizer: nil, listTargets: true)
        guard let output = try Process.captureOutput(
            binary, [], environment: environment, inheritStandardError: true
        ) else {
            throw FuzzError("Could not discover fuzz targets in \(String(reflecting: product)); see the executable's diagnostic above.")
        }
        let targets = output
            .split(separator: "\n")
            .map(String.init)
        guard !targets.isEmpty else {
            throw FuzzError("\(String(reflecting: product)) did not report any fuzz targets.")
        }
        if let error = TargetIdentity.validationError(targets) { throw FuzzError(error) }
        return Executable(product: product, binary: binary, targets: targets)
    }

    /// Every fuzz target in the package, validated before selecting any one.
    /// Building all products is necessary to detect cross-product collisions.
    func all() throws -> [Executable] {
        let executables = try products.map { try inspect($0) }
        if let error = TargetIdentity.validationError(executables.flatMap(\.targets)) {
            throw FuzzError(error)
        }
        return executables
    }

    func resolve(requested: String?) throws -> Resolution {
        guard !products.isEmpty else {
            throw FuzzError("""
                This package declares no fuzz targets.
                Add one with: swift package fuzz-init <Name>
                """)
        }

        // No product-name shortcut: it could hide a duplicate in another binary.
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
        // Logical target names win over product aliases. A product is a useful
        // shorthand only when it holds a single target and no target has that name.
        if let executable = executables.first(where: { $0.product == requested }) {
            if executable.targets.count == 1 {
                return Resolution(binary: executable.binary, target: executable.targets[0])
            }
            throw FuzzError("\(String(reflecting: requested)) registers several targets. Pick one: \(executable.targets.joined(separator: ", ")).")
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
