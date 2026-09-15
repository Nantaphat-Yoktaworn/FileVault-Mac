import Foundation
import Testing
@testable import VaultCore

@Test("recognizes all established vault magic values")
func recognizesKnownMagicValues() throws {
    #expect(try VaultFormat.detect(Data("NNNN1".utf8)) == .v1)
    #expect(try VaultFormat.detect(Data("NNNN2".utf8)) == .v2)
    #expect(try VaultFormat.detect(Data("NNNN3".utf8)) == .v3)
}

@Test("rejects unsupported magic values")
func rejectsUnknownMagicValue() {
    #expect(throws: VaultError.unsupportedFormat) {
        try VaultFormat.detect(Data("OTHER".utf8))
    }
}
