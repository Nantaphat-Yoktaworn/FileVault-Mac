import CommonCrypto
import CryptoKit
import Foundation

public enum VaultVersion: Equatable, Sendable {
    case v1
    case v2
    case v3
}

public enum VaultError: Error, Equatable, Sendable {
    case unsupportedFormat
    case malformedVault
    case authenticationFailed
    case invalidEntry
    case cancelled
}

public struct VaultEntry: Equatable, Sendable {
    public let path: String
    public let bytes: Data

    public init(path: String, bytes: Data) {
        self.path = path
        self.bytes = bytes
    }
}

public enum VaultOutputResolution: Sendable {
    case keepBoth
    case replace
    case cancel
}

public enum VaultOutput {
    public static func plannedDestination(for target: URL, resolution: VaultOutputResolution) throws -> URL? {
        let manager = FileManager.default
        guard resolution != .cancel else { return nil }
        guard manager.fileExists(atPath: target.path), resolution == .keepBoth else { return target }

        let directory = target.deletingLastPathComponent()
        let extensionName = target.pathExtension
        let stem = target.deletingPathExtension().lastPathComponent
        for index in 2...10_000 {
            let filename = extensionName.isEmpty ? "\(stem) \(index)" : "\(stem) \(index).\(extensionName)"
            let candidate = directory.appending(path: filename)
            if !manager.fileExists(atPath: candidate.path) { return candidate }
        }
        throw VaultError.invalidEntry
    }

    public static func restore(entries: [VaultEntry], outputDirectory: URL, shouldCancel: () -> Bool = { false }) throws {
        guard !entries.isEmpty else { throw VaultError.invalidEntry }
        let temporary = temporarySibling(of: outputDirectory)
        var published = false
        defer { if !published { try? FileManager.default.removeItem(at: temporary) } }
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        for entry in entries {
            guard !shouldCancel() else { throw VaultError.cancelled }
            let path = try safeRelativePath(entry.path)
            let destination = temporary.appending(path: path)
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
            try entry.bytes.write(to: destination, options: .atomic)
        }
        guard !shouldCancel() else { throw VaultError.cancelled }
        try publish(temporary: temporary, to: outputDirectory)
        published = true
    }

    public static func write(_ data: Data, to destination: URL, shouldCancel: () -> Bool = { false }) throws {
        guard !shouldCancel() else { throw VaultError.cancelled }
        let temporary = temporarySibling(of: destination)
        var published = false
        defer { if !published { try? FileManager.default.removeItem(at: temporary) } }
        try data.write(to: temporary, options: .atomic)
        guard !shouldCancel() else { throw VaultError.cancelled }
        try publish(temporary: temporary, to: destination)
        published = true
    }

    static func temporarySibling(of target: URL) -> URL {
        target.deletingLastPathComponent().appendingPathComponent(".\(target.lastPathComponent).\(UUID().uuidString).tmp")
    }

    static func publish(temporary: URL, to destination: URL) throws {
        let manager = FileManager.default
        if manager.fileExists(atPath: destination.path) {
            _ = try manager.replaceItemAt(destination, withItemAt: temporary)
        } else {
            try manager.moveItem(at: temporary, to: destination)
        }
    }

    @discardableResult
    static func safeRelativePath(_ path: String) throws -> String {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.hasPrefix("/"), !parts.isEmpty, !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else { throw VaultError.invalidEntry }
        return parts.joined(separator: "/")
    }
}

public enum VaultFormat {
    public static func detect(_ magic: Data) throws -> VaultVersion {
        switch magic {
        case Data("NNNN1".utf8): return .v1
        case Data("NNNN2".utf8): return .v2
        case Data("NNNN3".utf8): return .v3
        default: throw VaultError.unsupportedFormat
        }
    }
}

public enum VaultCodec {
    private static let iterations: UInt32 = 600_000
    private static let headerLength = 33

    public static func encryptV2(entries: [VaultEntry], password: String) throws -> Data {
        guard !entries.isEmpty, entries.count <= UInt16.max else { throw VaultError.invalidEntry }
        var plaintext = Data()
        plaintext.appendUInt16(UInt16(entries.count))
        for entry in entries {
            let name = Data(entry.path.utf8)
            guard !name.isEmpty, name.count <= Int(UInt16.max), entry.bytes.count <= Int(UInt32.max) else {
                throw VaultError.invalidEntry
            }
            plaintext.appendUInt16(UInt16(name.count))
            plaintext.append(name)
            plaintext.appendUInt32(UInt32(entry.bytes.count))
            plaintext.append(entry.bytes)
        }
        let salt = random(count: 16)
        let nonce = random(count: 12)
        let key = try deriveKey(password: password, salt: salt)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: try AES.GCM.Nonce(data: nonce))
        var vault = Data("NNNN2".utf8)
        vault.append(salt)
        vault.append(nonce)
        vault.append(sealed.ciphertext)
        vault.append(sealed.tag)
        return vault
    }

    public static func decrypt(vault: Data, password: String) throws -> [VaultEntry] {
        guard vault.count >= headerLength + 16 else { throw VaultError.malformedVault }
        let version = try VaultFormat.detect(vault.prefix(5))
        guard version == .v1 || version == .v2 else { throw VaultError.unsupportedFormat }
        let salt = vault.subdata(in: 5..<21)
        let nonce = vault.subdata(in: 21..<33)
        let cipherAndTag = vault.dropFirst(headerLength)
        guard cipherAndTag.count >= 16 else { throw VaultError.malformedVault }
        let ciphertext = Data(cipherAndTag.dropLast(16))
        let tag = Data(cipherAndTag.suffix(16))
        let key = try deriveKey(password: password, salt: salt)
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
            plaintext = try AES.GCM.open(box, using: key)
        } catch {
            throw VaultError.authenticationFailed
        }
        return try version == .v1 ? decodeV1(plaintext) : decodeV2(plaintext)
    }

    private static func decodeV1(_ plaintext: Data) throws -> [VaultEntry] {
        var reader = ByteReader(plaintext)
        let nameLength = Int(try reader.readUInt16())
        let name = try reader.readData(count: nameLength)
        guard let path = String(data: name, encoding: .utf8), !path.isEmpty else { throw VaultError.malformedVault }
        return [VaultEntry(path: path, bytes: reader.readRemaining())]
    }

    private static func decodeV2(_ plaintext: Data) throws -> [VaultEntry] {
        var reader = ByteReader(plaintext)
        let count = Int(try reader.readUInt16())
        guard count > 0 else { throw VaultError.malformedVault }
        var entries: [VaultEntry] = []
        entries.reserveCapacity(count)
        for _ in 0..<count {
            let nameLength = Int(try reader.readUInt16())
            let name = try reader.readData(count: nameLength)
            guard let path = String(data: name, encoding: .utf8), !path.isEmpty else { throw VaultError.malformedVault }
            let size = Int(try reader.readUInt32())
            entries.append(VaultEntry(path: path, bytes: try reader.readData(count: size)))
        }
        guard reader.isAtEnd else { throw VaultError.malformedVault }
        return entries
    }

    private static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: 32)
        let passwordBytes = Array(password.utf8)
        let status = salt.withUnsafeBytes { saltBuffer in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passwordBytes, passwordBytes.count,
                saltBuffer.bindMemory(to: UInt8.self).baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                &derived, derived.count
            )
        }
        guard status == kCCSuccess else { throw VaultError.malformedVault }
        return SymmetricKey(data: Data(derived))
    }

    private static func random(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: .min ... .max) })
    }
}

private struct ByteReader {
    private let data: Data
    private var offset = 0

    init(_ data: Data) { self.data = data }
    var isAtEnd: Bool { offset == data.count }

    mutating func readUInt16() throws -> UInt16 {
        let bytes = try readData(count: 2)
        return (UInt16(bytes[bytes.startIndex]) << 8) | UInt16(bytes[bytes.startIndex + 1])
    }

    mutating func readUInt32() throws -> UInt32 {
        let bytes = try readData(count: 4)
        return bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    mutating func readData(count: Int) throws -> Data {
        guard count >= 0, count <= data.count - offset else { throw VaultError.malformedVault }
        defer { offset += count }
        return data.subdata(in: offset..<(offset + count))
    }

    mutating func readRemaining() -> Data {
        let result = data.dropFirst(offset)
        offset = data.count
        return Data(result)
    }
}

extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }

    mutating func appendUInt32(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xff))
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }
}
