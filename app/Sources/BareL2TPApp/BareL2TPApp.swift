import SwiftUI

@main
struct BareL2TPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel.shared
    @AppStorage(AppPreferenceKeys.menuBarIconEnabled) private var menuBarIconEnabled = true

    var body: some Scene {
        Window("BareL2TP", id: "configuration") {
            ContentView()
                .environmentObject(model)
        }
        .defaultSize(width: 920, height: 690)
        .commands { ConnectionCommands(model: model) }

        MenuBarExtra(isInserted: $menuBarIconEnabled) {
            MenuBarContent()
                .environmentObject(model)
        } label: {
            // The menu bar shows only a monochrome symbol; the icon itself conveys the status.
            Image(systemName: model.status.symbol)
                .accessibilityLabel("BareL2TP · \(model.status.title)")
        }
        .menuBarExtraStyle(.window)
    }
}

/// Connection commands in the main menu. The menu bar icon can be turned off, so the main menu is
/// the entry point that is always available to keyboard users.
private struct ConnectionCommands: Commands {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandMenu("Connect") {
            Button("Connect VPN") { model.connect() }
                .keyboardShortcut("k")
                .disabled(model.status.isBusy || model.status.canDisconnect)
            Button("Disconnect VPN") { model.disconnect() }
                .keyboardShortcut("k", modifiers: [.command, .shift])
                .disabled(!model.status.canDisconnect)

            Divider()

            Button("Connection Settings…") { open(.account) }
                .keyboardShortcut(",")
            Button("Subnets…") { open(.routes) }
            Button("Log…") { open(.diagnostics) }
                .keyboardShortcut("l")
        }
    }

    /// Opens the main window at the given section. The app may be hidden in the menu bar, so the
    /// Dock icon is restored first.
    private func open(_ section: AppSection) {
        model.section = section
        NSApplication.shared.setActivationPolicy(.regular)
        openWindow(id: "configuration")
        NSApplication.shared.activate(ignoringOtherApps: true)
    }
}
