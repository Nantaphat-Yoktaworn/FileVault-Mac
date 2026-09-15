import Foundation
import Testing
@testable import VaultCore

@Test("v2 vault round-trips UTF-8 file names and binary payloads")
func v2RoundTripPreservesEntries() throws {
    let entries = [
        VaultEntry(path: "docs/hello.txt", bytes: Data("hello vault".utf8)),
        VaultEntry(path: "my cat 🐱.jpg", bytes: Data([0, 1, 2, 255])),
        VaultEntry(path: "empty.bin", bytes: Data())
    ]

    let vault = try VaultCodec.encryptV2(entries: entries, password: "p@ssw0rd 🔑123")
    #expect(vault.prefix(5) == Data("NNNN2".utf8))

    let decoded = try VaultCodec.decrypt(vault: vault, password: "p@ssw0rd 🔑123")
    #expect(decoded == entries)
}

@Test("v2 vault rejects a wrong password")
func v2RejectsWrongPassword() throws {
    let vault = try VaultCodec.encryptV2(
        entries: [VaultEntry(path: "secret.txt", bytes: Data("secret".utf8))],
        password: "correct"
    )

    #expect(throws: VaultError.authenticationFailed) {
        try VaultCodec.decrypt(vault: vault, password: "wrong")
    }
}

@Test("entry restoration is atomic and cleans up when cancelled")
func restorationCancellationLeavesNoOutput() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let output = root.appending(path: "restored")

    #expect(throws: VaultError.cancelled) {
        try VaultOutput.restore(
            entries: [VaultEntry(path: "docs/one.txt", bytes: Data("one".utf8))],
            outputDirectory: output,
            shouldCancel: { true }
        )
    }
    #expect(!FileManager.default.fileExists(atPath: output.path))
}

@Test("output planner keeps both by making a unique sibling name")
func outputPlannerKeepsBoth() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let target = root.appending(path: "vault.nnnn")
    try Data().write(to: target)

    let planned = try VaultOutput.plannedDestination(for: target, resolution: .keepBoth)
    #expect(planned?.lastPathComponent == "vault 2.nnnn")
    #expect(try VaultOutput.plannedDestination(for: target, resolution: .cancel) == nil)
    #expect(try VaultOutput.plannedDestination(for: target, resolution: .replace) == target)
}

@Test("atomic restoration replaces an existing destination only at publication")
func restorationReplacePublishesNewDirectory() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let output = root.appending(path: "restored")
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    try Data("old".utf8).write(to: output.appending(path: "stale.txt"))

    try VaultOutput.restore(entries: [VaultEntry(path: "fresh.txt", bytes: Data("new".utf8))], outputDirectory: output)

    #expect(try Data(contentsOf: output.appending(path: "fresh.txt")) == Data("new".utf8))
    #expect(!FileManager.default.fileExists(atPath: output.appending(path: "stale.txt").path))
}
