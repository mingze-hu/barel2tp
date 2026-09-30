import AppKit
import SwiftUI

struct MenuBarContent: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            statusPanel
            connectionButton

            Divider().padding(.vertical, 1)

            VStack(alignment: .leading, spacing: 1) {
                menuRow(L("Open Main Window"), symbol: "macwindow") {
                    showMainWindow()
                }
                menuRow(L("Connection Settings…"), symbol: "person.badge.key") {
                    showMainWindow(section: .account)
                }
                menuRow(L("Log…"), symbol: "waveform.path.ecg") {
                    showMainWindow(section: .diagnostics)
                }
            }
            .padding(.horizontal, -8)

            Divider().padding(.vertical, 1)

            VStack(alignment: .leading, spacing: 1) {
                menuRow(L("Hide Menu Bar Icon…"), symbol: "eye.slash") {
                    hideMenuBarIcon()
                }
                menuRow(L("Quit BareL2TP"), symbol: "power") {
                    dismissPanel()
                    quit()
                }
            }
            .padding(.horizontal, -8)
        }
        .padding(14)
        .frame(width: 276)
        .animation(Theme.transition, value: model.status)
        .task { model.start() }
    }

    private var header: some View {
        HStack(spacing: 10) {
            AppGlyph(size: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text("BareL2TP")
                    .font(.system(size: 13, weight: .semibold))
                HStack(spacing: 5) {
                    StatusDot(color: model.status.color, animated: model.status.isBusy, size: 6)
                    Text(model.status.title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
    }

    /// Status card. This is the only information visible while the app is hidden, so it first
    /// answers "connected to where, what is reachable, and for how long", and gives the reason
    /// directly when something goes wrong.
    private var statusPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "server.rack")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text(model.configuration.server.isEmpty ? L("No server set") : model.configuration.server)
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 0)
            }

            Text(statusDetail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if model.status == .connected, let since = model.connectedSince {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text("Connected \(elapsed(since: since, to: context.date))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.55), in: squircle(Theme.Radius.control))
        .overlay {
            squircle(Theme.Radius.control).strokeBorder(.separator.opacity(0.4), lineWidth: 1)
        }
    }

    /// In-progress states such as "Connecting" don't repeat the title; this line only appears when
    /// there is extra information.
    private var statusDetail: String {
        switch model.status {
        case .authorizing:
            return L("Enter this Mac's login password in the system dialog")
        case .failed:
            return model.lastFailure?.summary ?? L("The last connection failed")
        default:
            guard model.isConfigured else {
                return L("Still needed: \(model.missingEssentials.localizedList)")
            }
            let count = model.configuration.routes.count
            return count == 0 ? L("No subnets configured") : L("\(count) subnets")
        }
    }

    @ViewBuilder
    private var connectionButton: some View {
        if model.status.canDisconnect || model.status == .disconnecting {
            Button {
                model.disconnect()
            } label: {
                Label(disconnectLabel, systemImage: "stop.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
            .disabled(model.status == .disconnecting)
        } else if !model.isConfigured {
            // Required fields are still empty and connecting would fail, so take the user straight
            // to them.
            Button {
                showMainWindow(section: .account)
            } label: {
                Label("Finish Connection Settings", systemImage: "arrow.right")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        } else {
            Button {
                model.connect()
            } label: {
                Label(connectLabel, systemImage: "bolt.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.status.isBusy)
        }
    }

    private var disconnectLabel: String {
        switch model.status {
        case .connected: L("Disconnect")
        case .disconnecting: L("Disconnecting…")
        default: L("Cancel Connection")
        }
    }

    private var connectLabel: String {
        if case .failed = model.status { return L("Reconnect") }
        return L("Connect VPN")
    }

    private func menuRow(
        _ title: String,
        symbol: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
        }
        .buttonStyle(MenuRowButtonStyle())
    }

    /// Shows the main window, optionally switching to a section. The app may be hidden, so the Dock
    /// icon is restored first.
    private func showMainWindow(section: AppSection? = nil) {
        dismissPanel()
        if let section { model.section = section }
        NSApplication.shared.setActivationPolicy(.regular)
        openWindow(id: "configuration")
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    /// Dismisses the menu bar popover. Triggering an action from a button does not make SwiftUI
    /// close it automatically.
    ///
    /// It must go through dismiss(): calling close() on the panel destroys the MenuBarExtra window
    /// as well, and clicking the menu bar icon would then show nothing.
    private func dismissPanel() {
        dismiss()
    }

    /// Hides the menu bar icon. The icon is the only entry point while the app is hidden, and
    /// removing it outright would leave the app unreachable, so the user is first taken to the
    /// switch under General and the main window shows it being turned off.
    private func hideMenuBarIcon() {
        model.requestsMenuBarIconHide = true
        showMainWindow(section: .general)
    }

    /// Really quits the app instead of hiding it in the menu bar.
    private func quit() {
        TerminationIntent.isExplicit = true
        NSApplication.shared.terminate(nil)
    }

    private func elapsed(since: Date, to now: Date) -> String {
        let total = max(0, Int(now.timeIntervalSince(since)))
        return String(format: "%02d:%02d:%02d", total / 3600, (total % 3600) / 60, total % 60)
    }
}
