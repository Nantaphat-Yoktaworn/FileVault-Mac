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
