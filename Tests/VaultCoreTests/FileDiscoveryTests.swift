import Foundation
import Testing
@testable import VaultCore

@Test("folder discovery includes the selected root and skips .DS_Store")
func folderDiscoveryPreservesRootAndSkipsMetadata() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let photos = root.appending(path: "Photos")
    try FileManager.default.createDirectory(at: photos.appending(path: "nested"), withIntermediateDirectories: true)
    try Data("one".utf8).write(to: photos.appending(path: "cover.jpg"))
    try Data("two".utf8).write(to: photos.appending(path: "nested/detail.jpg"))
    try Data().write(to: photos.appending(path: ".DS_Store"))

    let sources = try VaultFileDiscovery.sources(for: [photos])

    #expect(sources.map(\.path).sorted() == ["Photos/cover.jpg", "Photos/nested/detail.jpg"])
    #expect(sources.map(\.size).reduce(0, +) == 6)
}

@Test("file discovery rejects duplicate selections")
func fileDiscoveryRejectsDuplicates() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let file = root.appending(path: "report.txt")
    try Data("report".utf8).write(to: file)

    #expect(throws: VaultError.invalidEntry) {
        try VaultFileDiscovery.sources(for: [file, file])
    }
}
