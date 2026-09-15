import Foundation
import Testing
@testable import VaultCore

@Test("v3 streaming vault round-trips files across chunk boundaries")
func v3StreamingRoundTrip() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    let input = root.appending(path: "input")
    let output = root.appending(path: "output")
    let vault = root.appending(path: "large.nnnn")
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: input, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

    let first = Data((0..<2_300).map { UInt8($0 % 251) })
    let second = Data("file boundary".utf8)
    let empty = Data()
    try first.write(to: input.appending(path: "first.bin"))
    try second.write(to: input.appending(path: "second.txt"))
    try empty.write(to: input.appending(path: "empty.bin"))

    let sources = try [
        VaultFileSource(url: input.appending(path: "first.bin"), path: "docs/first.bin"),
        VaultFileSource(url: input.appending(path: "second.txt"), path: "second.txt"),
        VaultFileSource(url: input.appending(path: "empty.bin"), path: "empty.bin")
    ]
    try VaultStreaming.encrypt(inputs: sources, password: "stream password", destination: vault, chunkSize: 1_000)
    let restored = try VaultStreaming.decrypt(vault: vault, password: "stream password", outputDirectory: output)

    #expect(restored.count == 3)
    #expect(try Data(contentsOf: output.appending(path: "docs/first.bin")) == first)
    #expect(try Data(contentsOf: output.appending(path: "second.txt")) == second)
    #expect(try Data(contentsOf: output.appending(path: "empty.bin")) == empty)
}

@Test("v3 streaming vault rejects a modified chunk")
func v3RejectsTampering() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let sourceURL = root.appending(path: "source.bin")
    let vault = root.appending(path: "vault.nnnn")
    try Data(repeating: 7, count: 2_000).write(to: sourceURL)
    try VaultStreaming.encrypt(inputs: [VaultFileSource(url: sourceURL, path: "source.bin")], password: "password", destination: vault, chunkSize: 1_000)
    var corrupt = try Data(contentsOf: vault)
    corrupt[corrupt.count - 1] ^= 0xff
    try corrupt.write(to: vault, options: .atomic)

    #expect(throws: VaultError.authenticationFailed) {
        try VaultStreaming.decrypt(vault: vault, password: "password", outputDirectory: root.appending(path: "out"))
    }
}
