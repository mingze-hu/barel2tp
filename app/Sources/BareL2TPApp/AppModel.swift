import AppKit
import Combine
import Foundation
import SwiftUI

enum VPNStatus: Equatable {
    case disconnected
    case authorizing
    case connecting
    case connected
    case disconnecting
    case failed(String)

    var title: String {
        switch self {
        case .disconnected: L("Disconnected")
        case .authorizing: L("Waiting for Authorization")
        case .connecting: L("Connecting")
        case .connected: L("Connected")
        case .disconnecting: L("Disconnecting")
        case .failed: L("Connection Failed")
        }
    }

    var symbol: String {
        switch self {
        case .connected: "lock.shield.fill"
        case .authorizing, .connecting, .disconnecting: "arrow.triangle.2.circlepath"
        case .failed: "exclamationmark.triangle.fill"
        case .disconnected: "lock.slash"
        }
    }

    var color: Color {
        switch self {
        case .connected: .green
        case .authorizing, .connecting, .disconnecting: .orange
        case .failed: .red
        case .disconnected: .secondary
        }
    }

    var isBusy: Bool {
        switch self {
        case .authorizing, .connecting, .disconnecting: true
        default: false
        }
    }

    var canDisconnect: Bool {
        switch self {
        case .authorizing, .connecting, .connected: true
        default: false
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    /// Shared instance. AppDelegate lives outside the SwiftUI scene and needs a stable entry point
    /// to close the tunnel during quit.
    static let shared = AppModel()

    @Published var configuration: VPNConfiguration
    @Published var password = ""
    @Published var rememberPassword = false
    @Published private(set) var status = VPNStatus.disconnected {
        didSet {
            guard status != oldValue else { return }
            // Record when the connection was established so the overview can show the connected
            // duration.
            if status == .connected {
                if connectedSince == nil { connectedSince = Date() }
            } else {
                connectedSince = nil
            }
        }
    }
    @Published private(set) var connectedSince: Date?
    @Published private(set) var logText = ""
    @Published var presentedError: PresentedError?

    /// Reason and advice for the most recent failure. The overview uses it to tell the user what to
    /// do next.
    @Published private(set) var lastFailure: ConnectionFailure?

    /// Whether a previous abnormal exit left routes that were not rolled back.
    @Published private(set) var hasLeftoverRoutes = false
    /// The button is disabled while cleanup runs, so a double click cannot open two authorization
    /// dialogs.
    @Published private(set) var isCleaningLeftovers = false

    /// Section currently shown in the main window. Menu bar actions need to take the user to a
    /// specific page, so it is shared through the model.
    @Published var section = AppSection.overview

    /// The menu bar asked to hide its own icon. The main window takes over and shows the switch
    /// being turned off.
    @Published var requestsMenuBarIconHide = false

    private let paths: AppPaths
    private let settings: SettingsStore
    private let keychain = KeychainStore()
    private let backend: BackendRunner
    private var connectTask: Task<Void, Never>?
    private var monitorTask: Task<Void, Never>?
    private var configurationSaveTask: Task<Void, Never>?
    private var shutdownTask: Task<Bool, Never>?
    private var started = false

    /// - Parameter loadsSavedPassword: Whether to read the saved password from the Keychain. The
    ///   test process gets a new code signature on every build, and reading the Keychain would show
    ///   an authorization dialog nobody answers and hang, so tests turn this off.
    init(loadsSavedPassword: Bool = true) {
        let paths = AppPaths()
        self.paths = paths
        settings = SettingsStore(paths: paths)
        backend = BackendRunner(paths: paths)
        configuration = (try? settings.load()) ?? VPNConfiguration()
        if loadsSavedPassword, let saved = try? keychain.readPassword(), !saved.isEmpty {
            password = saved
            rememberPassword = true
        }
    }

    deinit {
        connectTask?.cancel()
        monitorTask?.cancel()
        configurationSaveTask?.cancel()
    }

    func start() {
        guard !started else { return }
        started = true
        logText = backend.readLog()
        refreshLeftoverRoutes()
        if backend.isRunning() {
            // The backend is started with --daemon, so a running process means the tunnel is
            // already up.
            status = .connected
            beginMonitoring()
        }
    }

    func connect() {
        guard connectTask == nil, !status.isBusy, !status.canDisconnect else { return }
        connectTask = Task { [weak self] in
            guard let self else { return }
            defer { connectTask = nil }
            await connectNow()
        }
    }

    func disconnect() {
        guard status.canDisconnect else { return }
        let launch = connectTask
        launch?.cancel()
        monitorTask?.cancel()
        status = .disconnecting
        Task { [weak self] in
            guard let self else { return }
            if let launch {
                await launch.value
            }
            do {
                let stopped = try await stopBackend(timeout: .seconds(15))
                guard stopped else {
                    throw BackendError.system(L("The connection process did not exit within 15 seconds. Try again later."))
                }
                backend.cleanupAfterExit()
                refreshLeftoverRoutes()
                status = .disconnected
            } catch {
                if backend.isRunning() {
                    status = .connected
                    beginMonitoring()
                    presentedError = PresentedError(
                        title: L("Couldn't Disconnect the VPN"),
                        message: error.localizedDescription,
                        showsLogShortcut: true
                    )
                } else {
                    backend.cleanupAfterExit()
                    refreshLeftoverRoutes()
                    status = .disconnected
                }
            }
        }
    }

    /// Whether the backend process is still running, including an existing connection taken over
    /// after the app restarts.
    var hasRunningBackend: Bool {
        backend.isRunning()
    }

    /// Required fields still missing before connecting, in the order they are filled in.
    /// The password is not written to the configuration file, so this can only be checked at the
    /// model level.
    var missingEssentials: [String] {
        var missing: [String] = []
        if configuration.server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.append(L("Server address"))
        }
        if configuration.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.append(L("Username"))
        }
        if password.isEmpty {
            missing.append(L("VPN password"))
        }
        return missing
    }

    /// Whether all required fields are filled in so the user can connect right away.
    var isConfigured: Bool { missingEssentials.isEmpty }

    /// Opens the folder with the configuration and log in Finder, so the log can be handed to a
    /// network administrator.
    func revealSupportFolder() {
        try? paths.prepare()
        if FileManager.default.fileExists(atPath: paths.log.path) {
            NSWorkspace.shared.activateFileViewerSelecting([paths.log])
        } else {
            NSWorkspace.shared.open(paths.supportDirectory)
        }
    }

    /// Closes the tunnel before the app quits. The backend runs independently as root, and quitting
    /// the UI alone would leave a modified routing table behind.
    func shutdownForTermination() async -> Bool {
        // Quitting twice in a row re-enters here; the second call just waits for the first one's
        // result.
        if let existing = shutdownTask {
            return await existing.value
        }
        let task = Task { await performShutdown() }
        shutdownTask = task
        let stopped = await task.value
        shutdownTask = nil
        return stopped
    }

    private func performShutdown() async -> Bool {
        // Cancel the authorization or connect command first and wait for its cleanup. If
        // authorization has just succeeded, the backend is still checked and disconnected normally
        // afterwards; the app must not quit just because the connect task ended.
        let launch = connectTask
        launch?.cancel()
        if let launch {
            await launch.value
        }
        guard backend.isRunning() else {
            backend.cleanupAfterExit()
            status = .disconnected
            return true
        }

        // Stop the monitoring loop, or a normal backend exit would be treated as a failure and show
        // an error.
        monitorTask?.cancel()
        status = .disconnecting
        do {
            guard try await stopBackend(timeout: .seconds(15)) else {
                throw BackendError.system(L("The connection process did not exit within 15 seconds"))
            }
        } catch {
            if !backend.isRunning() {
                backend.cleanupAfterExit()
                refreshLeftoverRoutes()
                status = .disconnected
                return true
            }
            // A user-initiated quit must not pretend the shutdown succeeded; keep the app and
            // monitoring loop so the user can retry.
            status = .connected
            beginMonitoring()
            presentedError = PresentedError(
                title: L("Can't Quit Yet"),
                message: L("The VPN has not been safely disconnected: \(error.localizedDescription)"),
                showsLogShortcut: true
            )
            return false
        }
        backend.cleanupAfterExit()
        refreshLeftoverRoutes()
        status = .disconnected
        return true
    }

    private func stopBackend(timeout: Duration) async throws -> Bool {
        guard backend.isRunning() else { return true }
        try await backend.sendDisconnect()
        return await waitForBackend(toBeRunning: false, timeout: timeout)
    }

    /// Polls until the backend reaches the given state and reports explicitly whether it did so
    /// within the time limit.
    private func waitForBackend(toBeRunning expected: Bool, timeout: Duration) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while backend.isRunning() != expected, clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(120))
        }
        return backend.isRunning() == expected
    }

    /// Whether leftover routes can be cleaned now. Not while connected, and not again while a
    /// cleanup is running.
    var canCleanupLeftovers: Bool {
        hasLeftoverRoutes && !isCleaningLeftovers && !status.canDisconnect && !status.isBusy
    }

    func refreshLeftoverRoutes() {
        hasLeftoverRoutes = backend.hasLeftoverRoutes()
    }

    /// Manually rolls back routes left by a previous abnormal exit; requires administrator
    /// authorization.
    func cleanupLeftovers() {
        guard canCleanupLeftovers else { return }
        isCleaningLeftovers = true
        Task {
            do {
                let output = try await backend.cleanupLeftovers()
                presentedError = PresentedError(
                    title: L("Leftover Routes Cleaned Up"),
                    message: output.isEmpty ? L("The routing table has been restored.") : output,
                    showsLogShortcut: false
                )
            } catch BackendError.authorizationCancelled {
                // Cancelled by the user; not an error.
            } catch {
                presentedError = PresentedError(
                    title: L("Couldn't Clean Up Leftover Routes"),
                    message: error.localizedDescription,
                    showsLogShortcut: false
                )
            }
            isCleaningLeftovers = false
            refreshLeftoverRoutes()
        }
    }

    func clearLog() {
        logText = ""
        try? Data().write(to: paths.log)
    }

    func scheduleConfigurationSave() {
        configurationSaveTask?.cancel()
        configurationSaveTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(450))
            guard !Task.isCancelled, let self else { return }
            try? settings.save(configuration)
        }
    }

    private func connectNow() async {
        do {
            try configuration.validate()
            guard !password.isEmpty else {
                throw ConfigurationError.invalid(L("Enter the VPN password"))
            }
            guard !password.contains(where: \.isNewline) else {
                throw ConfigurationError.invalid(L("The VPN password must not contain line breaks"))
            }
            try settings.save(configuration)
            if rememberPassword {
                try keychain.savePassword(password)
            } else {
                try keychain.deletePassword()
            }

            status = .authorizing
            logText = ""
            lastFailure = nil
            // The backend is started with --daemon and the command only returns once the tunnel is
            // up; stream the log meanwhile.
            let progress = beginLaunchProgress()
            defer { progress.cancel() }
            try await backend.launch(password: password)
            // The command returning means the tunnel is ready; no need to wait for another round of
            // the monitoring loop.
            logText = backend.readLog()
            status = .connected
            beginMonitoring()
        } catch BackendError.authorizationCancelled {
            // The user pressed "Cancel"; this is not an error, just go back to disconnected
            // quietly.
            status = .disconnected
        } catch is CancellationError {
            // The user pressed "Disconnect" during authorization or negotiation, and the disconnect
            // flow cancelled the connect task.
            if status != .disconnecting {
                status = .disconnected
            }
        } catch let error as BackendError where error.ranBackend {
            // Only when the backend actually ran does the log contain the reason this connection
            // failed.
            failAfterLaunch(error)
        } catch {
            // Backend not found, backend already running, configuration rejected, password pipe
            // creation failed: all of these happen before the backend starts, so the error itself
            // is the most accurate explanation.
            fail(error)
        }
    }

    /// It can take a dozen seconds between authorization and a working tunnel; streaming the
    /// backend log lets the user see progress.
    private func beginLaunchProgress() -> Task<Void, Never> {
        Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let text = backend.readLog()
                if !text.isEmpty {
                    logText = text
                    // The log has content, so authorization has passed and the backend is
                    // negotiating.
                    if status == .authorizing {
                        status = .connecting
                    }
                }
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
    }

    /// The backend has already run once, so its log usually holds the real reason, which is far
    /// more useful than the command's exit message.
    private func failAfterLaunch(_ error: Error) {
        logText = backend.readLog()
        guard let line = lastMeaningfulLogLine() else {
            fail(error)
            return
        }
        let failure = ConnectionFailure.describing(logLine: line)
        lastFailure = failure
        status = .failed(failure.summary)
        presentedError = PresentedError(
            title: L("Couldn't Connect the VPN"),
            message: failure.detail,
            showsLogShortcut: true
        )
    }

    private func beginMonitoring() {
        monitorTask?.cancel()
        monitorTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                logText = backend.readLog()
                if backend.isRunning() {
                    // As above: a running process means connected. The log is only for people;
                    // failing to read it (for example because of permissions) must not move the
                    // status back from "Connected" to "Connecting" and spin forever.
                    if status != .disconnecting {
                        status = .connected
                    }
                } else {
                    backend.cleanupAfterExit()
                    refreshLeftoverRoutes()
                    if status == .disconnecting {
                        status = .disconnected
                    } else {
                        // Whether the disconnect happened before or after the connection was
                        // established changes what the user should do.
                        let wasConnected = status == .connected
                        let failure = ConnectionFailure.describing(
                            logLine: lastMeaningfulLogLine() ?? ""
                        )
                        lastFailure = failure
                        status = .failed(failure.summary)
                        presentedError = PresentedError(
                            title: wasConnected ? L("VPN Disconnected") : L("Couldn't Connect the VPN"),
                            message: failure.detail,
                            showsLogShortcut: true
                        )
                    }
                    return
                }
                try? await Task.sleep(for: .milliseconds(700))
            }
        }
    }

    private func lastMeaningfulLogLine() -> String? {
        logText
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .last(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
    }

    /// The connection failed before it really started. The log has no trace of this attempt, so the
    /// user is not pointed at it.
    private func fail(_ error: Error) {
        // A rejection from the backend's --check is also a configuration problem and is treated
        // like the app's own validation.
        let isConfigurationIssue: Bool
        if error is ConfigurationError {
            isConfigurationIssue = true
        } else if case BackendError.configurationRejected = error {
            isConfigurationIssue = true
        } else {
            isConfigurationIssue = false
        }
        let failure = ConnectionFailure(
            summary: error.localizedDescription,
            advice: isConfigurationIssue ? L("Fix it, then click “Connect” again.") : nil
        )
        lastFailure = failure
        status = .failed(failure.summary)
        presentedError = PresentedError(
            title: isConfigurationIssue ? L("Settings Need Attention") : L("Couldn't Connect the VPN"),
            message: failure.detail,
            showsLogShortcut: false
        )
    }
}

struct PresentedError: Identifiable {
    let id = UUID()
    /// Dialog title: first tell the user what happened, then explain what to do in the body.
    let title: String
    let message: String
    /// Whether it is worth offering a button that jumps straight to the Log.
    let showsLogShortcut: Bool
}
