import AppKit
import CoreServices

/// Quit intent. Menu bar actions live on the SwiftUI side and the quit decision on the AppKit side;
/// a shared flag connects them instead of relying on casting `NSApp.delegate`, which is not
/// reliable.
@MainActor
enum TerminationIntent {
    /// true means this quit request should really end the process instead of hiding in the menu
    /// bar.
    static var isExplicit = false

    /// true means the quit was initiated by the system (shut down, restart, log out). Such a quit
    /// must not be blocked by a confirmation dialog.
    static var isSystemInitiated = false

    /// true means the app should start again once this quit completes, for example to apply a new
    /// UI language.
    static var relaunchesAfterQuit = false

    /// Quits and starts the app again. Goes through the normal quit flow, so an active connection
    /// is still confirmed with the user and disconnected cleanly.
    static func relaunch() {
        isExplicit = true
        relaunchesAfterQuit = true
        NSApplication.shared.terminate(nil)
    }

    /// Forgets the intent of a quit that was cancelled, so the next quit behaves normally.
    static func reset() {
        isExplicit = false
        relaunchesAfterQuit = false
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Stage of the quit flow, used to block duplicate quit requests.
    enum QuitPhase {
        /// No quit request is being handled.
        case idle
        /// The confirmation dialog is open, waiting for the user.
        case confirming
        /// The user confirmed; the VPN is being disconnected.
        case shuttingDown
    }

    /// Not private: unit tests need to construct the "quit in progress" state.
    var quitPhase = QuitPhase.idle


    func applicationDidFinishLaunching(_ notification: Notification) {
        AppPreferenceKeys.registerDefaults()
        // Shutting down and logging out must really quit, or they would block the system.
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willPowerOffNotification,
            object: nil,
            queue: .main
        ) { _ in
            MainActor.assumeIsolated {
                TerminationIntent.isExplicit = true
                TerminationIntent.isSystemInitiated = true
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        if !flag, let window = sender.windows.first(where: { $0.canBecomeKey }) {
            window.makeKeyAndOrderFront(nil)
        }
        return true
    }

    /// Whether this quit request should hide the UI instead of really quitting.
    ///
    /// The menu bar icon is the only entry point once the app is hidden, so hiding is only safe
    /// while it is shown; "Quit" in the menu bar and system shutdown or logout bypass this path.
    func hidesInsteadOfTerminating(menuBarIconEnabled: Bool) -> Bool {
        !TerminationIntent.isExplicit && !isSystemInitiatedQuit && menuBarIconEnabled
    }

    /// Whether this quit needs a confirmation from the user.
    ///
    /// Only ask when quitting really has consequences: the VPN is connected or connecting. Without
    /// a connection the dialog would just get in the way. System shutdown, restart and logout must
    /// go through directly, or they would stall the system.
    func needsQuitConfirmation(hasActiveConnection: Bool) -> Bool {
        hasActiveConnection && !TerminationIntent.isSystemInitiated && !isSystemInitiatedQuit
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // A quit is already being handled: pressing the shortcut again while the dialog is open
        // must not bypass it, and the dialog must not reappear during shutdown. Both cases cancel
        // this request and let the first one finish.
        guard quitPhase == .idle else { return .terminateCancel }

        if hidesInsteadOfTerminating(menuBarIconEnabled: AppPreferenceKeys.menuBarIconIsEnabled) {
            hideToMenuBar(sender)
            return .terminateCancel
        }

        let model = AppModel.shared
        let hasActiveConnection = model.hasRunningBackend || model.status.isBusy
        if needsQuitConfirmation(hasActiveConnection: hasActiveConnection) {
            quitPhase = .confirming
            let confirmed = userConfirmsQuit(isConnecting: !model.hasRunningBackend)
            quitPhase = .idle
            guard confirmed else {
                // Reset the quit intent, or the next Cmd+Q would skip hiding in the menu bar and
                // quit directly.
                TerminationIntent.reset()
                return .terminateCancel
            }
        }

        guard hasActiveConnection else { return .terminateNow }
        // The Apple Event is only reliable during this callback, so capture the system quit intent
        // before the asynchronous shutdown starts.
        let mustTerminateForSystem = TerminationIntent.isSystemInitiated || isSystemInitiatedQuit
        quitPhase = .shuttingDown
        Task {
            let stopped = await model.shutdownForTermination()
            if !stopped, !mustTerminateForSystem {
                // If the graceful disconnect fails, cancel this quit; the still-running privileged
                // backend and its routes must not be abandoned.
                quitPhase = .idle
                TerminationIntent.reset()
            }
            sender.reply(toApplicationShouldTerminate: stopped || mustTerminateForSystem)
        }
        return .terminateLater
    }

    func applicationWillTerminate(_ notification: Notification) {
        guard TerminationIntent.relaunchesAfterQuit else { return }
        // A detached shell waits for this process to exit and then opens the bundle again;
        // launching directly would just activate the instance that is still quitting.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            "-c",
            "while /bin/kill -0 \"$0\" 2>/dev/null; do /bin/sleep 0.2; done; /usr/bin/open \"$1\"",
            String(ProcessInfo.processInfo.processIdentifier),
            Bundle.main.bundlePath,
        ]
        try? process.run()
    }

    /// Shows the quit confirmation. The title states the consequence and the main button says
    /// exactly what will happen. The app may be hidden in the menu bar, so it activates itself
    /// first to bring the dialog to the front.
    private func userConfirmsQuit(isConnecting: Bool) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning
        if isConnecting {
            alert.messageText = L("Cancel the connection and quit?")
            alert.informativeText = L("The VPN connection in progress will be cancelled.")
            alert.addButton(withTitle: L("Cancel and Quit"))
        } else {
            alert.messageText = L("Disconnect the VPN and quit?")
            alert.informativeText = L("You will lose access to the remote network, and routes will be restored to how they were before connecting.")
            alert.addButton(withTitle: L("Disconnect and Quit"))
        }
        alert.addButton(withTitle: L("Cancel"))

        NSApplication.shared.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// Closes the main window and removes the Dock icon, leaving only the menu bar icon.
    private func hideToMenuBar(_ sender: NSApplication) {
        // The MenuBarExtra panel can never become the main window; this condition excludes it.
        for window in sender.windows where window.canBecomeMain {
            window.close()
        }
        sender.setActivationPolicy(.accessory)
    }

    /// Whether the quit request comes from a system shutdown, restart or logout.
    private var isSystemInitiatedQuit: Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventID == AEEventID(kAEQuitApplication),
              let reason = event.attributeDescriptor(forKeyword: AEKeyword(kAEQuitReason))
        else { return false }

        let systemReasons: Set<OSType> = [
            OSType(kAELogOut),
            OSType(kAEReallyLogOut),
            OSType(kAEShowRestartDialog),
            OSType(kAEShowShutdownDialog),
            OSType(kAERestart),
            OSType(kAEShutDown),
        ]
        return systemReasons.contains(reason.enumCodeValue)
    }
}
