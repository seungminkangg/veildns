import AppKit
import SwiftUI

@main
struct VeilDNSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel()

    var body: some Scene {
        Window("VeilDNS", id: "main") {
            MainView(model: model)
                .preferredColorScheme(model.settings.appearance == "dark" ? .dark : model.settings.appearance == "light" ? .light : nil)
                .task { AppDelegate.model = model; model.initialize() }
        }
        .defaultSize(width: 900, height: 760)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(replacing: .appInfo) {
                Button("VeilDNS 정보") { NSApp.orderFrontStandardAboutPanel(nil) }
            }
        }

        MenuBarExtra("VeilDNS", systemImage: model.isActive ? "shield.lefthalf.filled" : "shield") {
            MenuContent(model: model)
        }
        .menuBarExtraStyle(.menu)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    static weak var model: AppModel?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model = Self.model else { return .terminateNow }
        if model.state == .idle { return .terminateNow }
        Task {
            let safe = await model.prepareToQuit()
            if safe { sender.reply(toApplicationShouldTerminate: true); return }
            if model.isBusy {
                sender.reply(toApplicationShouldTerminate: false)
                return
            }
            let alert = NSAlert()
            alert.messageText = "네트워크 설정 복구가 필요합니다"
            alert.informativeText = "복구를 완료하면 원래 설정으로 돌아갑니다. 지금 종료해도 복구 기록은 보관되며 다음 실행에서 복구할 수 있습니다."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "앱에서 복구")
            alert.addButton(withTitle: "기록을 남기고 종료")
            sender.reply(toApplicationShouldTerminate: alert.runModal() == .alertSecondButtonReturn)
        }
        return .terminateLater
    }
}

private struct MenuContent: View {
    @Bindable var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.statusTitle)
        if model.isActive { Text(model.journalServiceLabel) }
        Divider()
        Button(model.isActive ? "연결 중지" : "연결 시작") {
            Task { if model.isActive { await model.stop() } else { await model.start() } }
        }
        .disabled(model.isBusy || model.state == .recovery)
        if model.state == .recovery {
            Button("이전 네트워크 설정 복구") { Task { await model.recover() } }
        }
        Button("VeilDNS 열기") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Button("VeilDNS 종료") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

private extension AppModel {
    var journalServiceLabel: String { selectedService?.name ?? "선택한 네트워크" }
}
