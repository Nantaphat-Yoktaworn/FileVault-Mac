import CommonCrypto
import CryptoKit
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

@Test("v3 streaming encryption stops before publishing a vault when cancelled")
func v3StreamingCancellationLeavesNoVault() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let sourceURL = root.appending(path: "source.bin")
    let vault = root.appending(path: "vault.nnnn")
    try Data(repeating: 7, count: 2_000).write(to: sourceURL)

    #expect(throws: VaultError.cancelled) {
        try VaultStreaming.encrypt(
            inputs: [VaultFileSource(url: sourceURL, path: "source.bin")],
            password: "password",
            destination: vault,
            chunkSize: 1_000,
            shouldCancel: { true }
        )
    }
    #expect(!FileManager.default.fileExists(atPath: vault.path))
}

@Test("v3 streaming decryption removes temporary output after authentication failure")
func v3DecryptionFailureLeavesNoOutput() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let sourceURL = root.appending(path: "source.bin")
    let vault = root.appending(path: "vault.nnnn")
    let output = root.appending(path: "restored")
    try Data(repeating: 9, count: 2_000).write(to: sourceURL)
    try VaultStreaming.encrypt(inputs: [VaultFileSource(url: sourceURL, path: "source.bin")], password: "password", destination: vault, chunkSize: 1_000)
    var corrupt = try Data(contentsOf: vault)
    corrupt[corrupt.count - 1] ^= 0xff
    try corrupt.write(to: vault, options: .atomic)

    #expect(throws: VaultError.authenticationFailed) {
        try VaultStreaming.decrypt(vault: vault, password: "password", outputDirectory: output)
    }
    #expect(!FileManager.default.fileExists(atPath: output.path))
}

@Test("v3 streaming decryption removes temporary output when cancelled")
func v3DecryptionCancellationLeavesNoOutput() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let sourceURL = root.appending(path: "source.bin")
    let vault = root.appending(path: "vault.nnnn")
    let output = root.appending(path: "restored")
    try Data(repeating: 9, count: 2_000).write(to: sourceURL)
    try VaultStreaming.encrypt(inputs: [VaultFileSource(url: sourceURL, path: "source.bin")], password: "password", destination: vault, chunkSize: 1_000)

    #expect(throws: VaultError.cancelled) {
        try VaultStreaming.decrypt(vault: vault, password: "password", outputDirectory: output, shouldCancel: { true })
    }
    #expect(!FileManager.default.fileExists(atPath: output.path))
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

@Test("v3 streaming encryption rejects unsafe relative paths")
func v3EncryptionRejectsUnsafeRelativePaths() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let sourceURL = root.appending(path: "source.bin")
    let vault = root.appending(path: "vault.nnnn")
    try Data("abc".utf8).write(to: sourceURL)

    let unsafePaths = [
        ".",
        "./file.txt",
        "docs/./file.txt",
        "docs//file.txt",
        "docs/",
        "/abs/file.txt",
        "../escape.txt",
        "docs/../escape.txt"
    ]

    for unsafePath in unsafePaths {
        let source = try VaultFileSource(url: sourceURL, path: unsafePath)
        #expect(throws: VaultError.invalidEntry) {
            try VaultStreaming.encrypt(inputs: [source], password: "password", destination: vault, chunkSize: 1_000)
        }
        #expect(!FileManager.default.fileExists(atPath: vault.path))
    }
}

@Test("v3 streaming decryption rejects unsafe relative paths in manifest")
func v3DecryptionRejectsUnsafeRelativePaths() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

    let unsafePaths = [
        "",
        ".",
        "./file.txt",
        "docs/./file.txt",
        "docs//file.txt",
        "docs/",
        "/abs/file.txt",
        "../escape.txt",
        "docs/../escape.txt"
    ]

    for (index, unsafePath) in unsafePaths.enumerated() {
        let vault = root.appending(path: "unsafe-\(index).nnnn")
        let output = root.appending(path: "out-\(index)")
        try writeSyntheticEmptyV3Vault(entryName: unsafePath, password: "password", to: vault)

        #expect(throws: VaultError.invalidEntry) {
            try VaultStreaming.decrypt(vault: vault, password: "password", outputDirectory: output)
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }
}

private func writeSyntheticEmptyV3Vault(entryName: String, password: String, to destination: URL) throws {
    struct ManifestFile: Encodable { let name: String; let size: UInt64 }
    struct Manifest: Encodable { let v: Int; let chunkSize: Int; let totalSize: UInt64; let files: [ManifestFile] }

    let salt = Data(repeating: 0x11, count: 16)
    let prefix = Data(repeating: 0x22, count: 8)
    let chunkSize = 1_024
    let passwordBytes = Array(password.utf8)
    var derived = [UInt8](repeating: 0, count: 32)
    let status = salt.withUnsafeBytes { saltBuffer in
        CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordBytes, passwordBytes.count,
            saltBuffer.bindMemory(to: UInt8.self).baseAddress, salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000,
            &derived, derived.count
        )
    }
    precondition(status == kCCSuccess)
    let key = SymmetricKey(data: Data(derived))

    let manifestBytes = try JSONEncoder().encode(
        Manifest(v: 3, chunkSize: chunkSize, totalSize: 0, files: [ManifestFile(name: entryName, size: 0)])
    )
    var nonceBytes = prefix
    nonceBytes.append(contentsOf: [0, 0, 0, 0])
    let aad = Data([0, 0, 0, 0, 0])
    let sealed = try AES.GCM.seal(manifestBytes, using: key, nonce: try AES.GCM.Nonce(data: nonceBytes), authenticating: aad)
    let manifestCipher = sealed.ciphertext + sealed.tag

    var vault = Data("NNNN3".utf8)
    vault.append(salt)
    vault.append(prefix)
    for shift in [24, 16, 8, 0] {
        vault.append(UInt8((UInt32(chunkSize) >> shift) & 0xff))
    }
    for shift in [24, 16, 8, 0] {
        vault.append(UInt8((UInt32(manifestCipher.count) >> shift) & 0xff))
    }
    vault.append(manifestCipher)
    try vault.write(to: destination, options: .atomic)
}
