import CommonCrypto
import CryptoKit
import Foundation

public struct VaultFileSource: Sendable {
    public let url: URL
    public let path: String
    public let size: UInt64

    public init(url: URL, path: String) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let number = attributes[.size] as? NSNumber else { throw VaultError.invalidEntry }
        try self.init(url: url, path: path, size: number.uint64Value)
    }

    public init(url: URL, path: String, size: UInt64) throws {
        guard !path.isEmpty else { throw VaultError.invalidEntry }
        self.url = url
        self.path = path
        self.size = size
    }
}

public enum VaultStreaming {
    public static let defaultChunkSize = 64 * 1024 * 1024
    public static let iOSDefaultChunkSize = 4 * 1024 * 1024
    private static let fixedHeaderLength = 37
    private static let maxChunkSize = 0x1000_0000
    private static let iterations: UInt32 = 600_000

    public static func encrypt(
        inputs: [VaultFileSource],
        password: String,
        destination: URL,
        chunkSize: Int = defaultChunkSize,
        progress: ((UInt64, UInt64) -> Void)? = nil,
        shouldCancel: () -> Bool = { false }
    ) throws {
        guard !shouldCancel() else { throw VaultError.cancelled }
        guard !inputs.isEmpty, chunkSize > 0, chunkSize <= maxChunkSize else { throw VaultError.invalidEntry }
        for source in inputs { try validateRelativePath(source.path) }
        let total = try inputs.reduce(UInt64(0)) { try checkedAdd($0, $1.size) }
        let salt = random(count: 16)
        let prefix = random(count: 8)
        let key = try deriveKey(password: password, salt: salt)
        let manifest = StreamManifest(
            v: 3,
            chunkSize: chunkSize,
            totalSize: total,
            files: inputs.map { ManifestFile(name: $0.path, size: $0.size) }
        )
        let manifestBytes = try JSONEncoder().encode(manifest)
        let manifestCipher = try seal(manifestBytes, key: key, prefix: prefix, counter: 0, isLast: false)

        let temporary = VaultOutput.temporarySibling(of: destination)
        FileManager.default.createFile(atPath: temporary.path, contents: nil)
        let output = try FileHandle(forWritingTo: temporary)
        var published = false
        defer {
            try? output.close()
            if !published { try? FileManager.default.removeItem(at: temporary) }
        }
        var header = Data("NNNN3".utf8)
        header.append(salt)
        header.append(prefix)
        header.appendUInt32(UInt32(chunkSize))
        header.appendUInt32(UInt32(manifestCipher.count))
        try output.write(contentsOf: header)
        try output.write(contentsOf: manifestCipher)

        let totalChunks = total == 0 ? 0 : (total + UInt64(chunkSize) - 1) / UInt64(chunkSize)
        var counter: UInt32 = 0
        var complete: UInt64 = 0
        var pending = Data()
        for source in inputs {
            guard !shouldCancel() else { throw VaultError.cancelled }
            let input = try FileHandle(forReadingFrom: source.url)
            defer { try? input.close() }
            while let bytes = try input.read(upToCount: min(chunkSize - pending.count, 1_048_576)), !bytes.isEmpty {
                guard !shouldCancel() else { throw VaultError.cancelled }
                pending.append(bytes)
                if pending.count == chunkSize {
                    counter += 1
                    let cipher = try seal(pending, key: key, prefix: prefix, counter: counter, isLast: UInt64(counter) == totalChunks)
                    try output.write(contentsOf: cipher)
                    complete = try checkedAdd(complete, UInt64(pending.count))
                    progress?(complete, total)
                    pending.removeAll(keepingCapacity: true)
                }
            }
        }
        guard !shouldCancel() else { throw VaultError.cancelled }
        if !pending.isEmpty {
            counter += 1
            let cipher = try seal(pending, key: key, prefix: prefix, counter: counter, isLast: true)
            try output.write(contentsOf: cipher)
            complete = try checkedAdd(complete, UInt64(pending.count))
            progress?(complete, total)
        }
        guard UInt64(counter) == totalChunks, complete == total else { throw VaultError.malformedVault }
        guard !shouldCancel() else { throw VaultError.cancelled }
        try output.close()
        try VaultOutput.publish(temporary: temporary, to: destination)
        published = true
    }

    @discardableResult
    public static func decrypt(
        vault: URL,
        password: String,
        outputDirectory: URL,
        progress: ((UInt64, UInt64) -> Void)? = nil,
        shouldCancel: () -> Bool = { false }
    ) throws -> [URL] {
        guard !shouldCancel() else { throw VaultError.cancelled }
        let input = try FileHandle(forReadingFrom: vault)
        defer { try? input.close() }
        let header = try readExactly(input, count: fixedHeaderLength)
        guard try VaultFormat.detect(header.prefix(5)) == .v3 else { throw VaultError.unsupportedFormat }
        let salt = header.subdata(in: 5..<21)
        let prefix = header.subdata(in: 21..<29)
        let chunkSize = Int(header.readUInt32(at: 29))
        let manifestLength = Int(header.readUInt32(at: 33))
        guard chunkSize > 0, chunkSize <= maxChunkSize, manifestLength >= 16 else { throw VaultError.malformedVault }

        let key = try deriveKey(password: password, salt: salt)
        let manifestCipher = try readExactly(input, count: manifestLength)
        let manifestBytes = try open(manifestCipher, key: key, prefix: prefix, counter: 0, isLast: false)
        let manifest: StreamManifest
        do { manifest = try JSONDecoder().decode(StreamManifest.self, from: manifestBytes) }
        catch { throw VaultError.malformedVault }
        guard manifest.v == 3, manifest.chunkSize == chunkSize, !manifest.files.isEmpty else { throw VaultError.malformedVault }
        let total = try manifest.files.reduce(UInt64(0)) { try checkedAdd($0, $1.size) }
        guard total == manifest.totalSize else { throw VaultError.malformedVault }
        for file in manifest.files { try validateRelativePath(file.name) }

        let temporary = VaultOutput.temporarySibling(of: outputDirectory)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        var published = false
        defer {
            if !published { try? FileManager.default.removeItem(at: temporary) }
        }
        var restored: [URL] = []
        var fileIndex = 0
        var remaining: UInt64 = 0
        var output: FileHandle?
        func openNext() throws {
            guard !shouldCancel() else { throw VaultError.cancelled }
            try output?.close()
            output = nil
            while fileIndex < manifest.files.count {
                let file = manifest.files[fileIndex]
                let url = temporary.appending(path: file.name)
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                FileManager.default.createFile(atPath: url.path, contents: nil)
                restored.append(url)
                fileIndex += 1
                remaining = file.size
                if remaining > 0 {
                    output = try FileHandle(forWritingTo: url)
                    return
                }
            }
        }
        try openNext()

        let chunks = total == 0 ? 0 : (total + UInt64(chunkSize) - 1) / UInt64(chunkSize)
        var complete: UInt64 = 0
        if chunks > UInt64(UInt32.max) { throw VaultError.malformedVault }
        for i in 1...Int(chunks) {
            guard !shouldCancel() else { throw VaultError.cancelled }
            let plainLength = Int(min(UInt64(chunkSize), total - UInt64(i - 1) * UInt64(chunkSize)))
            let cipher = try readExactly(input, count: plainLength + 16)
            let plain = try open(cipher, key: key, prefix: prefix, counter: UInt32(i), isLast: i == Int(chunks))
            guard plain.count == plainLength else { throw VaultError.malformedVault }
            var offset = 0
            while offset < plain.count {
                guard let active = output else { throw VaultError.malformedVault }
                let take = Int(min(UInt64(plain.count - offset), remaining))
                guard take > 0 else { throw VaultError.malformedVault }
                try active.write(contentsOf: plain.subdata(in: offset..<(offset + take)))
                offset += take
                remaining -= UInt64(take)
                if remaining == 0 { try openNext() }
            }
            complete = try checkedAdd(complete, UInt64(plain.count))
            progress?(complete, total)
        }
        try output?.close()
        output = nil
        guard fileIndex == manifest.files.count, complete == total, (try input.read(upToCount: 1) ?? Data()).isEmpty else {
            throw VaultError.malformedVault
        }
        guard !shouldCancel() else { throw VaultError.cancelled }
        try VaultOutput.publish(temporary: temporary, to: outputDirectory)
        published = true
        return restored.map { outputDirectory.appending(path: String($0.path.dropFirst(temporary.path.count + 1))) }
    }

    private static func seal(_ plain: Data, key: SymmetricKey, prefix: Data, counter: UInt32, isLast: Bool) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: nonce(prefix: prefix, counter: counter))
        let box = try AES.GCM.seal(plain, using: key, nonce: nonce, authenticating: aad(counter: counter, isLast: isLast))
        return box.ciphertext + box.tag
    }

    private static func open(_ cipher: Data, key: SymmetricKey, prefix: Data, counter: UInt32, isLast: Bool) throws -> Data {
        guard cipher.count >= 16 else { throw VaultError.malformedVault }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce(prefix: prefix, counter: counter)),
                ciphertext: cipher.dropLast(16), tag: cipher.suffix(16)
            )
            return try AES.GCM.open(box, using: key, authenticating: aad(counter: counter, isLast: isLast))
        } catch {
            throw VaultError.authenticationFailed
        }
    }

    private static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: 32)
        let passwordBytes = Array(password.utf8)
        let status = salt.withUnsafeBytes { saltBuffer in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordBytes, passwordBytes.count,
                saltBuffer.bindMemory(to: UInt8.self).baseAddress, salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &derived, derived.count)
        }
        guard status == kCCSuccess else { throw VaultError.malformedVault }
        return SymmetricKey(data: Data(derived))
    }

    private static func nonce(prefix: Data, counter: UInt32) -> Data {
        var data = prefix
        data.appendUInt32(counter)
        return data
    }

    private static func aad(counter: UInt32, isLast: Bool) -> Data {
        var data = Data()
        data.appendUInt32(counter)
        data.append(isLast ? 1 : 0)
        return data
    }

    private static func random(count: Int) -> Data { Data((0..<count).map { _ in UInt8.random(in: .min ... .max) }) }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        guard count >= 0, let data = try handle.read(upToCount: count), data.count == count else { throw VaultError.malformedVault }
        return data
    }

    private static func checkedAdd(_ lhs: UInt64, _ rhs: UInt64) throws -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else { throw VaultError.malformedVault }
        return sum
    }

    private static func validateRelativePath(_ path: String) throws {
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        guard !path.hasPrefix("/"), !components.isEmpty, !components.contains("..") else { throw VaultError.invalidEntry }
    }
}

private struct StreamManifest: Codable {
    let v: Int
    let chunkSize: Int
    let totalSize: UInt64
    let files: [ManifestFile]
}

private struct ManifestFile: Codable {
    let name: String
    let size: UInt64
}

private extension Data {
    func readUInt32(at offset: Int) -> UInt32 {
        precondition(offset + 4 <= count)
        return self[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
}
