import Foundation
import SwiftUI
import UniformTypeIdentifiers
import UIKit
#if canImport(VaultCore)
import VaultCore
#endif

@main
struct FileVaultiOSApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

private enum VaultMode: String, CaseIterable, Identifiable {
    case encrypt = "Encrypt"
    case decrypt = "Decrypt"
    var id: String { rawValue }
}

private final class CancellationToken: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    func isCancelled() -> Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

private final class SecurityScopedURLs {
    private var accessed: [URL] = []

    init(_ urls: [URL]) throws {
        for url in urls where url.startAccessingSecurityScopedResource() {
            accessed.append(url)
        }
    }

    deinit { release() }

    private func release() {
        for url in accessed { url.stopAccessingSecurityScopedResource() }
        accessed.removeAll()
    }
}

private struct FolderPicker: UIViewControllerRepresentable {
    let onPick: (URL?) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onPick: onPick) }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder], asCopy: false)
        picker.allowsMultipleSelection = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPick: (URL?) -> Void
        init(onPick: @escaping (URL?) -> Void) { self.onPick = onPick }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) { onPick(urls.first) }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { onPick(nil) }
    }
}

private struct ExportPicker: UIViewControllerRepresentable {
    let url: URL
    let onFinish: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onFinish: onFinish) }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forExporting: [url], asCopy: true)
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onFinish: () -> Void
        init(onFinish: @escaping () -> Void) { self.onFinish = onFinish }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { onFinish() }
    }
}

private struct ContentView: View {
    @State private var mode: VaultMode = .encrypt
    @State private var selectedURLs: [URL] = []
    @State private var destinationURL: URL?
    @State private var password = ""
    @State private var confirmation = ""
    @State private var status = "Choose files or folders to encrypt."
    @State private var processedBytes: UInt64 = 0
    @State private var totalBytes: UInt64 = 0
    @State private var isWorking = false
    @State private var cancellation: CancellationToken?
    @State private var showsImporter = false
    @State private var showsFolderPicker = false
    @State private var exportURL: URL?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Mode", selection: $mode) {
                        ForEach(VaultMode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .onChange(of: mode) { _, _ in reset() }
                }

                Section(mode == .encrypt ? "Files to encrypt" : "Vault to decrypt") {
                    Button(mode == .encrypt ? "Choose Files or Folder" : "Choose .nnnn Vault") { showsImporter = true }
                    if selectedURLs.isEmpty {
                        Text("Nothing selected").foregroundStyle(.secondary)
                    } else {
                        ForEach(selectedURLs, id: \.self) { url in
                            Label(url.lastPathComponent, systemImage: url.hasDirectoryPath ? "folder" : "doc")
                                .lineLimit(1)
                        }
                        Button("Clear", role: .destructive) { selectedURLs.removeAll() }
                    }
                }

                if mode == .decrypt {
                    Section("Destination") {
                        Button("Choose Files Folder") { showsFolderPicker = true }
                        Text(destinationURL?.lastPathComponent ?? "No destination selected")
                            .foregroundStyle(.secondary)
                    }
                }

                Section("Password") {
                    SecureField(mode == .encrypt ? "Set password" : "Vault password", text: $password)
                    if mode == .encrypt {
                        SecureField("Confirm password", text: $confirmation)
                        if !confirmation.isEmpty && password != confirmation {
                            Text("Passwords do not match.").foregroundStyle(.red)
                        }
                    }
                }

                Section {
                    Button(mode == .encrypt ? "Encrypt to .nnnn" : "Decrypt") { runOperation() }
                        .disabled(!canRun)
                    if isWorking {
                        ProgressView(value: Double(processedBytes), total: Double(max(totalBytes, 1)))
                        Text("\(ByteCountFormatter.string(fromByteCount: Int64(processedBytes), countStyle: .file)) of \(ByteCountFormatter.string(fromByteCount: Int64(totalBytes), countStyle: .file))")
                            .font(.footnote).foregroundStyle(.secondary)
                        Button("Cancel", role: .cancel) { cancellation?.cancel() }
                    }
                }

                Section("Status") {
                    Text(status).foregroundStyle(status.hasPrefix("Error") ? .red : .secondary)
                }
            }
            .navigationTitle("FileVault")
        }
        .fileImporter(
            isPresented: $showsImporter,
            allowedContentTypes: mode == .encrypt ? [.item, .folder] : [UTType(filenameExtension: "nnnn") ?? .data],
            allowsMultipleSelection: mode == .encrypt
        ) { result in
            switch result {
            case .success(let urls):
                if mode == .decrypt && urls.count != 1 { status = "Error: choose one .nnnn vault." }
                else { selectedURLs = urls; status = "Selected \(urls.count) item\(urls.count == 1 ? "" : "s")." }
            case .failure(let error): status = "Error: \(error.localizedDescription)"
            }
        }
        .sheet(isPresented: $showsFolderPicker) {
            FolderPicker { url in
                showsFolderPicker = false
                destinationURL = url
            }
        }
        .sheet(isPresented: Binding(get: { exportURL != nil }, set: { if !$0 { exportURL = nil } })) {
            if let exportURL {
                ExportPicker(url: exportURL) {
                    try? FileManager.default.removeItem(at: exportURL)
                    self.exportURL = nil
                    status = "Vault export finished."
                }
            }
        }
        .onOpenURL { url in
            mode = .decrypt
            selectedURLs = [url]
            status = "Selected \(url.lastPathComponent)."
        }
    }

    private var canRun: Bool {
        !selectedURLs.isEmpty && !password.isEmpty && !isWorking && (mode == .decrypt ? destinationURL != nil : password == confirmation)
    }

    private func reset() {
        selectedURLs = []
        destinationURL = nil
        password = ""
        confirmation = ""
        status = mode == .encrypt ? "Choose files or folders to encrypt." : "Choose a .nnnn vault and destination folder."
    }

    private func runOperation() {
        let input = selectedURLs
        let target = destinationURL
        let secret = password
        let selectedMode = mode
        let token = CancellationToken()
        cancellation = token
        isWorking = true
        processedBytes = 0
        totalBytes = 0

        Task.detached {
            do {
                if selectedMode == .encrypt {
                    let scope = try SecurityScopedURLs(input)
                    _ = scope
                    let sources = try VaultFileDiscovery.sources(for: input)
                    let total = sources.reduce(UInt64(0)) { $0 + $1.size }
                    await updateProgress(0, total)
                    let temporary = FileManager.default.temporaryDirectory
                        .appending(path: Self.vaultExportFilename(for: input))
                    try VaultStreaming.encrypt(inputs: sources, password: secret, destination: temporary, chunkSize: VaultStreaming.iOSDefaultChunkSize, progress: { complete, total in
                        Task { await updateProgress(complete, total) }
                    }, shouldCancel: { token.isCancelled() })
                    await MainActor.run {
                        exportURL = temporary
                        status = "Choose where to save \(temporary.lastPathComponent)."
                        finish()
                    }
                } else {
                    guard let target else { throw VaultError.invalidEntry }
                    let scope = try SecurityScopedURLs(input + [target])
                    _ = scope
                    let destination = target.appending(path: input[0].deletingPathExtension().lastPathComponent)
                    let output = try VaultOutput.plannedDestination(for: destination, resolution: .keepBoth)
                    guard let output else { throw VaultError.cancelled }
                    let handle = try FileHandle(forReadingFrom: input[0])
                    let magic = try handle.read(upToCount: 5) ?? Data()
                    try handle.close()
                    switch try VaultFormat.detect(magic) {
                    case .v3:
                        _ = try VaultStreaming.decrypt(vault: input[0], password: secret, outputDirectory: output, progress: { complete, total in
                            Task { await updateProgress(complete, total) }
                        }, shouldCancel: { token.isCancelled() })
                    case .v1, .v2:
                        let size = (try FileManager.default.attributesOfItem(atPath: input[0].path)[.size] as? NSNumber)?.uint64Value ?? 0
                        await updateProgress(0, size)
                        let entries = try VaultCodec.decrypt(vault: Data(contentsOf: input[0], options: .mappedIfSafe), password: secret)
                        try VaultOutput.restore(entries: entries, outputDirectory: output, shouldCancel: { token.isCancelled() })
                        await updateProgress(size, size)
                    }
                    await MainActor.run { status = "Decrypted into \(output.lastPathComponent)."; finish() }
                }
            } catch {
                await MainActor.run {
                    status = (error as? VaultError) == .authenticationFailed ? "Error: Wrong password or damaged vault." : "Error: \(error.localizedDescription)"
                    finish()
                }
            }
        }
    }

    @MainActor private func updateProgress(_ complete: UInt64, _ total: UInt64) { processedBytes = complete; totalBytes = total }
    @MainActor private func finish() { isWorking = false; cancellation = nil; password = ""; confirmation = "" }

    nonisolated private static func vaultExportFilename(for input: [URL]) -> String {
        guard input.count == 1 else { return "FileVault.nnnn" }
        let filename = input[0].deletingPathExtension().lastPathComponent
        return filename.isEmpty ? "FileVault.nnnn" : "\(filename).nnnn"
    }
}
