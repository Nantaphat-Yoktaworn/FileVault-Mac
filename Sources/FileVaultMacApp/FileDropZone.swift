import AppKit
import SwiftUI

struct FileDropZone<Content: View>: NSViewRepresentable {
    let onDrop: ([URL]) -> Bool
    let content: Content

    init(onDrop: @escaping ([URL]) -> Bool, @ViewBuilder content: () -> Content) {
        self.onDrop = onDrop
        self.content = content()
    }

    func makeNSView(context: Context) -> HostingDropView<Content> {
        HostingDropView(rootView: content, onDrop: onDrop)
    }

    func updateNSView(_ view: HostingDropView<Content>, context: Context) {
        view.rootView = content
        view.onDrop = onDrop
    }
}

final class HostingDropView<Content: View>: NSHostingView<Content> {
    var onDrop: ([URL]) -> Bool

    init(rootView: Content, onDrop: @escaping ([URL]) -> Bool) {
        self.onDrop = onDrop
        super.init(rootView: rootView)
        registerForDraggedTypes([.fileURL])
    }

    required init(rootView: Content) {
        self.onDrop = { _ in false }
        super.init(rootView: rootView)
        registerForDraggedTypes([.fileURL])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        sender.draggingPasteboard.canReadObject(forClasses: [NSURL.self], options: nil) ? .copy : []
    }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        let urls = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: nil) as? [URL] ?? []
        return onDrop(urls)
    }
}
