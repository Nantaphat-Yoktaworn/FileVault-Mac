import Foundation
import XCTest
import FileVault

final class VaultFixtureTests: XCTestCase {
    private let password = "fixture-password"

    func testLegacyFixtureDecryptsOnIOS() throws {
        let entries = try VaultCodec.decrypt(vault: try fixtureData("legacy"), password: password)
        XCTAssertEqual(entries, [VaultEntry(path: "legacy.txt", bytes: Data("legacy fixture\n".utf8))])
    }

    func testPortableFixtureDecryptsOnIOS() throws {
        let entries = try VaultCodec.decrypt(vault: try fixtureData("portable"), password: password)
        XCTAssertEqual(entries, [
            VaultEntry(path: "docs/note.txt", bytes: Data("portable fixture\n".utf8)),
            VaultEntry(path: "empty.bin", bytes: Data())
        ])
    }

    func testStreamingFixtureDecryptsOnIOS() throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let vault = root.appending(path: "streaming.nnnn")
        try fixtureData("streaming").write(to: vault)

        _ = try VaultStreaming.decrypt(vault: vault, password: password, outputDirectory: root.appending(path: "out"))
        XCTAssertEqual(try Data(contentsOf: root.appending(path: "out/stream/data.txt")), Data("streaming fixture\n".utf8))
    }

    private func fixtureData(_ name: String) throws -> Data {
        guard let url = Bundle(for: Self.self).url(forResource: name, withExtension: "nnnn") else {
            throw NSError(domain: "VaultFixtureTests", code: 1)
        }
        return try Data(contentsOf: url)
    }
}
