import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers
#if canImport(VaultCore)
import VaultCore
#endif

@main
struct FileVaultMacApp: App {
    init() {
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    var body: some Scene {
        WindowGroup("FileVault") {
            ContentView()
                .frame(minWidth: 680, minHeight: 500)
                .onOpenURL { url in
                    NotificationCenter.default.post(name: .fileVaultOpenRequested, object: url)
                }
        }
    }
}

private extension Notification.Name {
    static let fileVaultOpenRequested = Notification.Name("FileVaultOpenRequested")
}

private final class CancellationToken: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    func isCancelled() -> Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

private struct NativeSecureField: NSViewRepresentable {
    let placeholder: String
    @Binding var text: String

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSSecureTextField {
        let field = NSSecureTextField()
        field.placeholderString = placeholder
        field.delegate = context.coordinator
        field.isBezeled = true
        field.isEditable = true
        field.isSelectable = true
        field.focusRingType = .default
        return field
    }

    func updateNSView(_ field: NSSecureTextField, context: Context) {
        if field.stringValue != text { field.stringValue = text }
        field.placeholderString = placeholder
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        private var parent: NativeSecureField
        init(_ parent: NativeSecureField) { self.parent = parent }
        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSecureTextField else { return }
            parent.text = field.stringValue
        }
    }
}

private struct ContentView: View {
    @State private var mode: Mode = .encrypt
    @State private var selectedURLs: [URL] = []
    @State private var password = ""
    @State private var confirmation = ""
    @State private var status = "Choose files to create a .nnnn vault."
    @State private var isWorking = false
    @State private var processedBytes: UInt64 = 0
    @State private var totalBytes: UInt64 = 0
    @State private var startedAt: Date?
    @State private var cancellation: CancellationToken?

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .center, spacing: 14) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 34, weight: .semibold))
                    .foregroundStyle(.tint)
                    .frame(width: 44, height: 44)
                    .background(.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 3) {
                    Text("FileVault").font(.largeTitle.bold())
                    Text("Local encryption. Passwords are never saved.")
                        .foregroundStyle(.secondary)
                }
            }

            Picker("Mode", selection: $mode) {
                Text("Encrypt").tag(Mode.encrypt)
                Text("Decrypt").tag(Mode.decrypt)
            }
            .pickerStyle(.segmented)
            .onChange(of: mode) { _, _ in reset() }

            FileDropZone(onDrop: handleDroppedURLs) {
                GroupBox(mode == .encrypt ? "Files to encrypt" : "Vault to decrypt") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 8) {
                            Button(mode == .encrypt ? "Choose Files…" : "Choose Vault…") { chooseInput() }
                            if mode == .encrypt { Button("Choose Folder…") { chooseFolder() } }
                            if !selectedURLs.isEmpty { Button("Clear") { selectedURLs.removeAll() } }
                            Spacer()
                        }
                        if selectedURLs.isEmpty {
                            Label("Drop files or folders here", systemImage: "arrow.down.doc")
                                .foregroundStyle(.secondary)
                        } else {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(selectedURLs, id: \.self) { url in
                                    Label(url.lastPathComponent, systemImage: url.hasDirectoryPath ? "folder.fill" : "doc.fill")
                                        .lineLimit(1)
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 5)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            NativeSecureField(placeholder: mode == .encrypt ? "Set password" : "Vault password", text: $password)
                .frame(height: 24)
            if mode == .encrypt {
                NativeSecureField(placeholder: "Confirm password", text: $confirmation).frame(height: 24)
            }

            HStack {
                Button(mode == .encrypt ? "Encrypt to .nnnn…" : "Decrypt to Folder…") { runOperation() }
                    .buttonStyle(.borderedProminent)
                    .disabled(selectedURLs.isEmpty || password.isEmpty || isWorking || (mode == .encrypt && password != confirmation))
                if isWorking {
                    ProgressView(value: totalBytes == 0 ? 0 : Double(processedBytes), total: Double(max(totalBytes, 1)))
                        .frame(maxWidth: 180)
                    Text("\(ByteCountFormatter.string(fromByteCount: Int64(processedBytes), countStyle: .file)) of \(ByteCountFormatter.string(fromByteCount: Int64(totalBytes), countStyle: .file))")
                        .font(.footnote).foregroundStyle(.secondary)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text("Elapsed \(Self.elapsedString(since: startedAt, now: context.date))")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Cancel") { cancellation?.cancel() }
                }
            }

            Divider()
            Text(status).textSelection(.enabled).foregroundStyle(status.hasPrefix("Error") ? .red : .secondary)
            Spacer()
            Text("Vaults over 512 MiB stream in 64 MiB chunks to keep memory use bounded.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .padding(28)
        .onReceive(NotificationCenter.default.publisher(for: .fileVaultOpenRequested)) { notification in
            guard let url = notification.object as? URL else { return }
            mode = .decrypt
            _ = handleDroppedURLs([url])
        }
    }

    private func reset() {
        selectedURLs.removeAll()
        password = ""
        confirmation = ""
        status = mode == .encrypt ? "Choose files to create a .nnnn vault." : "Choose an existing .nnnn vault."
    }

    private func handleDroppedURLs(_ urls: [URL]) -> Bool {
        let files = urls.filter { $0.isFileURL }
        guard !files.isEmpty else { return false }
        if mode == .decrypt {
            guard files.count == 1, files[0].pathExtension.lowercased() == "nnnn" else {
                status = "Error: drop one .nnnn vault."
                return false
            }
        }
        selectedURLs = files
        status = "Selected \(files.count) item\(files.count == 1 ? "" : "s")."
        return true
    }

    private func chooseInput() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = mode == .encrypt
        panel.allowedContentTypes = mode == .decrypt ? [UTType(filenameExtension: "nnnn") ?? .data] : []
        guard panel.runModal() == .OK else { return }
        _ = handleDroppedURLs(panel.urls)
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        _ = handleDroppedURLs([url])
    }

    private func runOperation() {
        guard mode == .decrypt || password == confirmation else { status = "Error: passwords do not match."; return }
        isWorking = true
        processedBytes = 0
        totalBytes = 0
        startedAt = Date()
        let input = selectedURLs
        let secret = password
        let selectedMode = mode
        let token = CancellationToken()
        cancellation = token
        Task.detached {
            do {
                if selectedMode == .encrypt {
                    let sources = try VaultFileDiscovery.sources(for: input)
                    let total = sources.reduce(UInt64(0)) { $0 + $1.size }
                    await updateProgress(0, total)
                    let selectedOutput = await chooseSaveURL(suggestedName: suggestedVaultName(for: input))
                    let output = await preflightDestination(selectedOutput)
                    guard let output else { await setStatus("Encryption cancelled."); return }
                    if total > 512 * 1024 * 1024 {
                        try VaultStreaming.encrypt(inputs: sources, password: secret, destination: output, progress: { complete, total in
                            Task { await updateProgress(complete, total) }
                        }, shouldCancel: { token.isCancelled() })
                    } else {
                        let entries = try sources.map {
                            guard !token.isCancelled() else { throw VaultError.cancelled }
                            return VaultEntry(path: $0.path, bytes: try Data(contentsOf: $0.url, options: .mappedIfSafe))
                        }
                        let vault = try VaultCodec.encryptV2(entries: entries, password: secret)
                        try VaultOutput.write(vault, to: output, shouldCancel: { token.isCancelled() })
                        await updateProgress(total, total)
                    }
                    await setStatus("Encrypted \(sources.count) file\(sources.count == 1 ? "" : "s") to \(output.lastPathComponent).")
                } else {
                    let handle = try FileHandle(forReadingFrom: input[0])
                    let magic = try handle.read(upToCount: 5) ?? Data()
                    try handle.close()
                    let version = try VaultFormat.detect(magic)
                    let folder = await chooseOutputFolder()
                    let output = await preflightDestination(folder?.appendingPathComponent(input[0].deletingPathExtension().lastPathComponent))
                    guard let output else { await setStatus("Decryption cancelled."); return }
                    if version == .v3 {
                        let restored = try VaultStreaming.decrypt(vault: input[0], password: secret, outputDirectory: output, progress: { complete, total in
                            Task { await updateProgress(complete, total) }
                        }, shouldCancel: { token.isCancelled() })
                        await setStatus("Decrypted \(restored.count) file\(restored.count == 1 ? "" : "s") into \(output.lastPathComponent).")
                    } else {
                        let size = (try FileManager.default.attributesOfItem(atPath: input[0].path)[.size] as? NSNumber)?.uint64Value ?? 0
                        await updateProgress(0, size)
                        let vault = try Data(contentsOf: input[0], options: .mappedIfSafe)
                        let entries = try VaultCodec.decrypt(vault: vault, password: secret)
                        try VaultOutput.restore(entries: entries, outputDirectory: output, shouldCancel: { token.isCancelled() })
                        await updateProgress(size, size)
                        await setStatus("Decrypted \(entries.count) file\(entries.count == 1 ? "" : "s") into \(output.lastPathComponent).")
                    }
                }
                await MainActor.run { password = ""; confirmation = "" }
            } catch {
                let message = (error as? VaultError) == .cancelled ? "Operation cancelled." : "Error: \(Self.displayError(error))"
                await setStatus(message)
            }
        }
    }

    @MainActor private func updateProgress(_ processed: UInt64, _ total: UInt64) { processedBytes = processed; totalBytes = total }
    @MainActor private func setStatus(_ message: String) { status = message; isWorking = false; cancellation = nil }

    @MainActor private func chooseSaveURL(suggestedName: String) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [UTType(filenameExtension: "nnnn") ?? .data]
        return panel.runModal() == .OK ? panel.url : nil
    }

    @MainActor private func chooseOutputFolder() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }

    @MainActor private func preflightDestination(_ target: URL?) -> URL? {
        guard let target else { return nil }
        guard FileManager.default.fileExists(atPath: target.path) else { return target }
        let alert = NSAlert()
        alert.messageText = "An item named \(target.lastPathComponent) already exists."
        alert.informativeText = "Keep Both creates a unique name. Replace overwrites only after processing succeeds."
        alert.addButton(withTitle: "Keep Both")
        alert.addButton(withTitle: "Replace")
        alert.addButton(withTitle: "Cancel")
        let resolution: VaultOutputResolution
        switch alert.runModal() {
        case .alertFirstButtonReturn: resolution = .keepBoth
        case .alertSecondButtonReturn: resolution = .replace
        default: resolution = .cancel
        }
        return try? VaultOutput.plannedDestination(for: target, resolution: resolution)
    }

    private func suggestedVaultName(for urls: [URL]) -> String {
        let base = urls.count == 1 ? urls[0].deletingPathExtension().lastPathComponent : "vault"
        return "\(base).nnnn"
    }

    private static func elapsedString(since startedAt: Date?, now: Date) -> String {
        let seconds = Int(now.timeIntervalSince(startedAt ?? now))
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    private nonisolated static func displayError(_ error: Error) -> String {
        switch error {
        case VaultError.authenticationFailed: return "Wrong password or damaged vault."
        case VaultError.unsupportedFormat: return "This vault format is not supported by this build."
        default: return error.localizedDescription
        }
    }

    private enum Mode { case encrypt, decrypt }
}
