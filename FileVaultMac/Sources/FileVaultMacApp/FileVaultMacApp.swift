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
        }
    }
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

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("FileVault")
                .font(.largeTitle.bold())
            Text("Encrypt locally. Passwords are never saved.")
                .foregroundStyle(.secondary)

            Picker("Mode", selection: $mode) {
                Text("Encrypt").tag(Mode.encrypt)
                Text("Decrypt").tag(Mode.decrypt)
            }
            .pickerStyle(.segmented)
            .onChange(of: mode) { _, _ in reset() }

            GroupBox(mode == .encrypt ? "Files to encrypt" : "Vault to decrypt") {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Button(mode == .encrypt ? "Choose Files…" : "Choose Vault…") { chooseInput() }
                        if mode == .encrypt { Button("Choose Folder…") { chooseFolder() } }
                        if !selectedURLs.isEmpty { Button("Clear") { selectedURLs.removeAll() } }
                    }
                    if selectedURLs.isEmpty {
                        Text("No file selected").foregroundStyle(.secondary)
                    } else {
                        ForEach(selectedURLs, id: \.self) { url in
                            Text(url.lastPathComponent).lineLimit(1)
                        }
                    }
                }
                .padding(.vertical, 4)
            }

            NativeSecureField(placeholder: mode == .encrypt ? "Set password" : "Vault password", text: $password)
                .frame(height: 24)
            if mode == .encrypt {
                NativeSecureField(placeholder: "Confirm password", text: $confirmation)
                    .frame(height: 24)
            }

            HStack {
                Button(mode == .encrypt ? "Encrypt to .nnnn…" : "Decrypt to Folder…") {
                    runOperation()
                }
                .buttonStyle(.borderedProminent)
                .disabled(selectedURLs.isEmpty || password.isEmpty || isWorking || (mode == .encrypt && password != confirmation))
                if isWorking { ProgressView().controlSize(.small) }
            }

            Divider()
            Text(status).textSelection(.enabled)
                .foregroundStyle(status.hasPrefix("Error") ? .red : .secondary)
            Spacer()
            Text("Vaults over 512 MiB stream in 64 MiB chunks to keep memory use bounded.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(28)
    }

    private func reset() {
        selectedURLs.removeAll()
        password = ""
        confirmation = ""
        status = mode == .encrypt ? "Choose files to create a .nnnn vault." : "Choose an existing .nnnn vault."
    }

    private func chooseInput() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = mode == .encrypt
        panel.allowedContentTypes = mode == .decrypt ? [UTType(filenameExtension: "nnnn") ?? .data] : []
        guard panel.runModal() == .OK else { return }
        selectedURLs = panel.urls
        status = "Selected \(selectedURLs.count) file\(selectedURLs.count == 1 ? "" : "s")."
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        selectedURLs = [url]
        status = "Selected folder \(url.lastPathComponent)."
    }

    private func runOperation() {
        guard mode == .decrypt || password == confirmation else {
            status = "Error: passwords do not match."
            return
        }
        isWorking = true
        let input = selectedURLs
        let secret = password
        let selectedMode = mode
        let vaultName = suggestedVaultName(for: input)
        Task.detached {
            do {
                if selectedMode == .encrypt {
                    let sources = try VaultFileDiscovery.sources(for: input)
                    let total = sources.reduce(UInt64(0)) { $0 + $1.size }
                    let output = await chooseSaveURL(suggestedName: vaultName)
                    guard let output else { await setStatus("Encryption cancelled."); return }
                    if total > 512 * 1024 * 1024 {
                        try VaultStreaming.encrypt(inputs: sources, password: secret, destination: output)
                    } else {
                        let entries = try sources.map { VaultEntry(path: $0.path, bytes: try Data(contentsOf: $0.url, options: .mappedIfSafe)) }
                        let vault = try VaultCodec.encryptV2(entries: entries, password: secret)
                        try vault.write(to: output, options: .atomic)
                    }
                    await setStatus("Encrypted \(sources.count) file\(sources.count == 1 ? "" : "s") to \(output.lastPathComponent).")
                } else {
                    let handle = try FileHandle(forReadingFrom: input[0])
                    let magic = try handle.read(upToCount: 5) ?? Data()
                    try handle.close()
                    let version = try VaultFormat.detect(magic)
                    let folder = await chooseOutputFolder()
                    guard let folder else { await setStatus("Decryption cancelled."); return }
                    if version == .v3 {
                        let restored = try VaultStreaming.decrypt(vault: input[0], password: secret, outputDirectory: folder)
                        await setStatus("Decrypted \(restored.count) file\(restored.count == 1 ? "" : "s") into \(folder.lastPathComponent).")
                    } else {
                        let vault = try Data(contentsOf: input[0], options: .mappedIfSafe)
                        let entries = try VaultCodec.decrypt(vault: vault, password: secret)
                        for entry in entries {
                            let relative = try Self.safeRelativePath(entry.path)
                            let output = folder.appending(path: relative)
                            try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
                            try entry.bytes.write(to: output, options: .withoutOverwriting)
                        }
                        await setStatus("Decrypted \(entries.count) file\(entries.count == 1 ? "" : "s") into \(folder.lastPathComponent).")
                    }
                }
                await MainActor.run { password = ""; confirmation = "" }
            } catch {
                await setStatus("Error: \(displayError(error))")
            }
        }
    }

    @MainActor private func setStatus(_ message: String) { status = message; isWorking = false }

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

    private func suggestedVaultName(for urls: [URL]) -> String {
        let base = urls.count == 1 ? urls[0].deletingPathExtension().lastPathComponent : "vault"
        return "\(base).nnnn"
    }

    private nonisolated static func safeRelativePath(_ path: String) throws -> String {
        let parts = path.split(separator: "/", omittingEmptySubsequences: true)
        guard !parts.isEmpty, !path.hasPrefix("/"), !parts.contains("..") else { throw OutputError.unsafePath }
        return parts.joined(separator: "/")
    }

    private func displayError(_ error: Error) -> String {
        switch error {
        case VaultError.authenticationFailed: return "Wrong password or damaged vault."
        case VaultError.unsupportedFormat: return "This vault format is not supported by this build."
        default: return error.localizedDescription
        }
    }

    private enum Mode { case encrypt, decrypt }
    private enum OutputError: Error { case unsafePath }
}
