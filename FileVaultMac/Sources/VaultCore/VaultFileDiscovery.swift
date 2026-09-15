import Foundation

public enum VaultFileDiscovery {
    public static func sources(for selectedURLs: [URL]) throws -> [VaultFileSource] {
        guard !selectedURLs.isEmpty else { throw VaultError.invalidEntry }
        var seen = Set<String>()
        var discovered: [VaultFileSource] = []
        for url in selectedURLs {
            let canonical = url.standardizedFileURL.resolvingSymlinksInPath()
            guard seen.insert(canonical.path).inserted else { throw VaultError.invalidEntry }
            let values = try canonical.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw VaultError.invalidEntry }
            if values.isDirectory == true {
                discovered.append(contentsOf: try sources(inFolder: canonical))
            } else if values.isRegularFile == true {
                discovered.append(try VaultFileSource(url: canonical, path: canonical.lastPathComponent))
            } else {
                throw VaultError.invalidEntry
            }
        }
        guard !discovered.isEmpty else { throw VaultError.invalidEntry }
        return discovered
    }

    private static func sources(inFolder folder: URL) throws -> [VaultFileSource] {
        let rootName = folder.lastPathComponent
        guard !rootName.isEmpty, rootName != ".", rootName != ".." else { throw VaultError.invalidEntry }
        guard let enumerator = FileManager.default.enumerator(
            at: folder,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else { throw VaultError.invalidEntry }

        var results: [VaultFileSource] = []
        for case let candidate as URL in enumerator {
            let fileURL = candidate.path.hasPrefix("/")
                ? candidate.standardizedFileURL
                : folder.appending(path: candidate.path).standardizedFileURL
            if fileURL.lastPathComponent == ".DS_Store" { continue }
            let values = try fileURL.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true {
                if values.isDirectory == true { enumerator.skipDescendants() }
                continue
            }
            if values.isDirectory == true { continue }
            guard values.isRegularFile == true else { continue }
            let relative = fileURL.path.dropFirst(folder.path.count + 1)
            guard !relative.isEmpty else { throw VaultError.invalidEntry }
            results.append(try VaultFileSource(url: fileURL, path: "\(rootName)/\(relative)"))
        }
        return results
    }
}
