import Darwin
import AppKit
import Foundation
import SwiftUI
import Testing
@testable import BareL2TPApp

@Test func newConfigurationHasNoRoutes() {
    let configuration = VPNConfiguration()
    #expect(configuration.routes.isEmpty)
}

@Test func configurationSerializesToBackendTOML() throws {
    var configuration = VPNConfiguration()
    configuration.server = "vpn.example.com"
    configuration.username = "alice"
    configuration.routesText = "10.0.0.0/8\n172.16.0.0/12"
    try configuration.validate()

    let result = configuration.toml()
    #expect(result.contains("server = \"vpn.example.com\""))
    #expect(result.contains("username = \"alice\""))
    #expect(result.contains("\"10.0.0.0/8\""))
    #expect(!result.contains("password"))
}

@Test func invalidRoutesAreFlaggedPerLine() {
    var configuration = VPNConfiguration()
    configuration.routesText = "10.20.0.0/16\n10.0.0.0/99\nnot a subnet"

    #expect(configuration.invalidRoutes == ["10.0.0.0/99", "not a subnet"])
}

@Test func restoringDefaultsOnlyAffectsAdvancedSettings() {
    var configuration = VPNConfiguration()
    configuration.server = "vpn.example.com"
    configuration.username = "user"
    configuration.routesText = "10.20.0.0/16"
    configuration.mtu = 1200
    configuration.requestDNS = true
    configuration.hostname = "mac"
    #expect(!configuration.usesDefaultAdvancedSettings)

    configuration.resetAdvancedSettings()

    #expect(configuration.usesDefaultAdvancedSettings)
    #expect(configuration.mtu == 1400)
    #expect(!configuration.requestDNS)
    #expect(configuration.hostname.isEmpty)
    // Server, account and routes are user data and must not be cleared along with them.
    #expect(configuration.server == "vpn.example.com")
    #expect(configuration.username == "user")
    #expect(configuration.routesText == "10.20.0.0/16")
}

@Test func backendLogBecomesActionableAdvice() {
    let authentication = ConnectionFailure.describing(
        logLine: "2026-08-28T02:11:22.123456Z ERROR CHAP-MD5 authentication failed: bad password"
    )
    #expect(authentication.summary == "The server rejected this account.")
    #expect(authentication.advice?.contains("Connection settings") == true)

    // Tunnel authentication is a different problem and must not be taken by the generic
    // "authentication" rule, or the user would be sent to fix the wrong thing.
    let tunnelSecret = ConnectionFailure.describing(
        logLine: "Error: server requires L2TP tunnel authentication, but only a PPP CHAP-MD5 password is configured"
    )
    #expect(tunnelSecret.summary.contains("tunnel secret"))

    // Unrecognized lines are shown as is, but without the timestamp and log level.
    let unknown = ConnectionFailure.describing(logLine: "2026-08-28T02:11:22.123456Z  WARN something unexpected")
    #expect(unknown.summary == "something unexpected")

    // Even when the backend exits silently, the user gets something actionable.
    #expect(ConnectionFailure.describing(logLine: "").advice != nil)
}

@Test(arguments: [
    ("Error: server requires L2TP tunnel authentication, but only a PPP CHAP-MD5 password is configured", "The server requires an L2TP tunnel secret."),
    ("Error: CHAP-MD5 authentication failed: bad password", "The server rejected this account."),
    ("Error: failed to resolve L2TP server vpn.example.com", "The VPN server could not be found."),
    ("Error: L2TP server vpn.example.com has no IPv4 address; only IPv4 outer transport is supported", "The VPN server could not be found."),
    ("Error: PPP LCP phase timed out after 5 waits", "The server did not respond and the connection timed out."),
    ("Error: failed to configure interface utun5; macOS usually needs sudo, Linux needs CAP_NET_ADMIN", "Couldn't create the VPN network interface: insufficient privileges."),
    ("Error: failed to install VPN routes", "Couldn't set up subnet routes."),
    ("Error: L2TP server closed the control tunnel", "The server closed the connection."),
])
func backendErrorsMapToFailureReasons(line: String, summary: String) {
    // The backend log is always in English; every rule must recognize the real error text.
    #expect(ConnectionFailure.describing(logLine: line).summary == summary)
}

/// Treats a resource directory in the repository as a bundle, so lookups, interpolation
/// and plural rules can be checked against the real translation files.
private func resourceBundle(_ name: String) -> Bundle {
    let resources = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Resources/\(name)")
    return Bundle(url: resources)!
}

private let englishBundle = resourceBundle("en.lproj")
private let chineseBundle = resourceBundle("zh-Hans.lproj")

private func english(_ key: String.LocalizationValue) -> String {
    String(localized: key, bundle: englishBundle, locale: Locale(identifier: "en"))
}

private func chinese(_ key: String.LocalizationValue) -> String {
    String(localized: key, bundle: chineseBundle, locale: Locale(identifier: "zh-Hans"))
}

@Test func chineseTranslationsResolveFromEnglishKeys() {
    #expect(chinese("Connection") == "连接设置")
    #expect(chinese("Still needed: \("服务器地址")") == "还需要填写：服务器地址")
    #expect(chinese("Subnet “\("10.0.0.0/99")” is invalid; use the form 10.20.0.0/16")
        == "网段“10.0.0.0/99”写法不对，正确写法形如 10.20.0.0/16")
    #expect(chinese("\(3) subnets") == "3 个内网网段")
    #expect(chinese("Connected via \("vpn.example.com:1701") with access to \(2) subnets.")
        == "正在通过 vpn.example.com:1701 访问 2 个内网网段。")
}

@Test func englishCountsUsePluralRules() {
    #expect(english("\(1) subnets") == "1 subnet")
    #expect(english("\(3) subnets") == "3 subnets")
    #expect(english("\(1) lines are invalid") == "1 line is invalid")
    #expect(english("\(2) lines are invalid") == "2 lines are invalid")
    #expect(english("Connected via \("vpn.example.com:1701") with access to \(1) subnets.")
        == "Connected via vpn.example.com:1701 with access to 1 subnet.")
}

@Test func rejectsInvalidRoutes() {
    var configuration = VPNConfiguration()
    configuration.server = "vpn.example.com"
    configuration.username = "user"
    configuration.routesText = "10.0.0.0/99"

    #expect(throws: ConfigurationError.self) {
        try configuration.validate()
    }
}

@Test func privilegedLaunchCommandIsValidShell() throws {
    let paths = AppPaths()
    let runner = BackendRunner(paths: paths)
    let binary = URL(fileURLWithPath: "/Applications/BareL2TP.app/Contents/Resources/barel2tp")
    let command = runner.privilegedLaunchCommand(binary: binary, uid: 501, cleansLeftovers: false)

    #expect(!command.contains("&;"))
    // The backend daemonizes itself, so the command must not contain shell background jobs
    // or a hand-written PID.
    #expect(command.contains("--daemon"))
    #expect(command.contains("--log-file"))
    #expect(command.contains("--pid-file"))
    #expect(command.contains("--state-file"))
    #expect(command.contains("--runtime-uid 501"))
    #expect(!command.contains(" & "))
    #expect(!command.contains("$!"))
    // Without leftovers there is no extra cleanup, so not every log starts with it.
    #expect(!command.contains("--cleanup"))

    for source in [command, runner.privilegedLaunchCommand(binary: binary, uid: 501, cleansLeftovers: true)] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-n", "-c", source]
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
    }
}

@Test func cleanupCommandUsesTheSameRuntimeFiles() throws {
    let paths = AppPaths()
    let runner = BackendRunner(paths: paths)
    let command = runner.privilegedCleanupCommand(
        binary: URL(fileURLWithPath: "/Applications/BareL2TP.app/Contents/Resources/barel2tp")
    )

    #expect(command.contains("--cleanup"))
    #expect(command.contains(paths.pid.path))
    #expect(command.contains(paths.state.path))
    // Cleaning up must not bring the tunnel up as a side effect.
    #expect(!command.contains("--daemon"))

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-n", "-c", command]
    try process.run()
    process.waitUntilExit()
    #expect(process.terminationStatus == 0)
}

@Test func launchCommandRollsBackLeftoversFirst() throws {
    let runner = BackendRunner(paths: AppPaths())
    let command = runner.privilegedLaunchCommand(
        binary: URL(fileURLWithPath: "/Applications/BareL2TP.app/Contents/Resources/barel2tp"),
        uid: 501,
        cleansLeftovers: true
    )

    #expect(command.contains("--cleanup"))
    // A failed cleanup (for example, stale records) must not block this connection.
    #expect(command.contains("|| true"))
    let cleanupIndex = try #require(command.range(of: "--cleanup")).lowerBound
    let daemonIndex = try #require(command.range(of: "--daemon")).lowerBound
    #expect(cleanupIndex < daemonIndex)
}

@Test func onlyFailedAuthorizationCommandsReadTheLog() throws {
    // The backend ran, so the log holds the real reason for this connection.
    #expect(BackendError.commandFailed("boom").ranBackend)
    // These all happen before the backend starts; the log would only show the previous connection.
    #expect(!BackendError.configurationRejected("routes is empty").ranBackend)
    #expect(!BackendError.alreadyRunning.ranBackend)
    #expect(!BackendError.binaryNotFound.ranBackend)
    #expect(!BackendError.system("Couldn't create the password pipe").ranBackend)
    #expect(!BackendError.authorizationCancelled.ranBackend)
}

@Test func onlyAppleScriptCancellationCountsAsUserCancel() throws {
    let cancelled = CommandResult(
        status: 1,
        stdout: "",
        stderr: "0:0: execution error: User canceled. (-128)\n"
    )
    guard case .authorizationCancelled = BackendRunner.failure(from: cancelled) else {
        Issue.record("a cancelled authorization should be recognized as authorizationCancelled")
        return
    }

    // "cancel" or a number like -128 in the backend log is a real failure and must not be swallowed.
    for noise in [
        "0:0: execution error: daemon failed to start; see /tmp/x.log for details (1)\nl2tp: peer cancelled the session",
        "0:0: execution error: connection failed: offset -128 out of range (1)",
    ] {
        let failed = CommandResult(status: 1, stdout: "", stderr: noise)
        guard case let .commandFailed(message) = BackendRunner.failure(from: failed) else {
            Issue.record("a real failure must not be treated as a user cancellation: \(noise)")
            return
        }
        #expect(!message.isEmpty)
    }
}

@Test func reusedProcessIDDoesNotCountAsRunningBackend() throws {
    // After the backend is force-killed the PID file stays behind, and that PID is eventually
    // reused. Looking only at kill(pid, 0), the UI would show "Connected" forever and block
    // both connecting and cleanup. The test process itself is "alive but not the backend".
    #expect(!BackendRunner.isBackend(pid: getpid()))
    // Without a path, conservatively assume the backend is alive, so a root backend is never
    // misjudged as stopped and started again.
    #expect(BackendRunner.isBackend(pid: Int32.max))

    let stalePID = FileManager.default.temporaryDirectory
        .appendingPathComponent("barel2tp-stale-\(UUID().uuidString).pid")
    defer { try? FileManager.default.removeItem(at: stalePID) }
    try "\(getpid())\n".write(to: stalePID, atomically: true, encoding: .utf8)
    // An unlocked file is a stale record, even if it happens to contain a live process ID.
    #expect(BackendRunner.readLockedPID(at: stalePID) == nil)
}

@Test func passwordIsDeliveredWhileAuthorizedProcessWaits() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("BareL2TPTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let fifo = directory.appendingPathComponent("password.fifo")
    let result = fifo.path.withCString { Darwin.mkfifo($0, mode_t(S_IRUSR | S_IWUSR)) }
    #expect(result == 0)

    let delivery = Task {
        try await BackendRunner.deliverPassword("test-password", to: fifo)
    }
    try await Task.sleep(for: .milliseconds(100))
    // Opening the FIFO blocks until a writer is ready. Running it on the cooperative pool
    // would hold a thread, and on machines with few cores deliverPassword would never get
    // to open the write end.
    let received = try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<String, Error>) in
        DispatchQueue.global(qos: .userInitiated).async {
            continuation.resume(with: Result {
                let handle = try FileHandle(forReadingFrom: fifo)
                defer { try? handle.close() }
                let data = try handle.read(upToCount: 128) ?? Data()
                return String(decoding: data, as: UTF8.self)
            })
        }
    }
    try await delivery.value

    #expect(received == "test-password\n")
}

@Test func nativeUnixDatagramSendsDisconnect() throws {
    let identifier = UUID().uuidString.prefix(8)
    let socketURL = URL(fileURLWithPath: "/tmp/barel2tp-\(identifier).sock")
    defer { try? FileManager.default.removeItem(at: socketURL) }

    let descriptor = Darwin.socket(AF_UNIX, SOCK_DGRAM, 0)
    #expect(descriptor >= 0)
    defer { Darwin.close(descriptor) }
    var address = try BackendRunner.unixSocketAddress(path: socketURL.path)
    let bindResult = withUnsafePointer(to: &address) { addressPointer in
        addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
            Darwin.bind(
                descriptor,
                socketAddress,
                socklen_t(MemoryLayout<sockaddr_un>.size)
            )
        }
    }
    #expect(bindResult == 0)

    try BackendRunner.sendControlMessage("disconnect", to: socketURL.path)
    var buffer = [UInt8](repeating: 0, count: 64)
    let length = Darwin.recv(descriptor, &buffer, buffer.count, 0)
    #expect(length == 10)
    #expect(String(decoding: buffer.prefix(Int(length)), as: UTF8.self) == "disconnect")
}

@Test func logStripsTerminalColorCodes() {
    let source = "\u{001B}[2m2026-08-28\u{001B}[0m \u{001B}[32mINFO\u{001B}[0m VPN ready"
    #expect(BackendRunner.stripANSI(source) == "2026-08-28 INFO VPN ready")
}

@Test func connectionCanBeCancelledDuringAuthorization() {
    #expect(VPNStatus.authorizing.canDisconnect)
    #expect(VPNStatus.connecting.canDisconnect)
    #expect(VPNStatus.connected.canDisconnect)
    #expect(!VPNStatus.disconnecting.canDisconnect)
}

@Test func largeCommandOutputDoesNotBlockPipes() async throws {
    let result = try await BackendRunner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
            "-c",
            "yes o | head -c 200000; yes e | head -c 200000 >&2",
        ]
    )
    #expect(result.status == 0)
    #expect(result.stdout.utf8.count == 200_000)
    #expect(result.stderr.utf8.count == 200_000)
}

@Test func cancellingCommandTerminatesChild() async throws {
    let clock = ContinuousClock()
    let started = clock.now
    let task = Task {
        try await BackendRunner.run(
            executable: URL(fileURLWithPath: "/bin/sleep"),
            arguments: ["30"]
        )
    }
    try await Task.sleep(for: .milliseconds(100))
    task.cancel()
    await #expect(throws: CancellationError.self) {
        try await task.value
    }
    #expect(started.duration(to: clock.now) < .seconds(3))
}

/// Renders every section offscreen. Besides leaving screenshots to inspect by eye, this
/// ensures every page can actually be drawn.
@Test @MainActor func everySectionRendersOffscreen() throws {
    let model = AppModel(loadsSavedPassword: false)
    model.configuration.server = "vpn.example.com"
    model.configuration.username = "mingze.hu"
    model.configuration.routesText = "10.20.0.0/16\n172.20.8.0/21"
    model.configuration.mtu = 1400

    for section in AppSection.allCases {
        model.section = section
        let rootView = ContentView()
            .environmentObject(model)
            .frame(width: 920, height: 690)
        let hostingView = NSHostingView(rootView: rootView)
        hostingView.frame = NSRect(x: 0, y: 0, width: 920, height: 690)
        let window = NSWindow(
            contentRect: hostingView.frame,
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.contentView = hostingView
        window.layoutIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.15))
        hostingView.layoutSubtreeIfNeeded()

        guard let representation = hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds) else {
            Issue.record("could not create a bitmap for \(section.title)")
            return
        }
        hostingView.cacheDisplay(in: hostingView.bounds, to: representation)
        guard let png = representation.representation(using: .png, properties: [:]) else {
            Issue.record("could not create a PNG for \(section.title)")
            return
        }
        try png.write(to: URL(fileURLWithPath: "/tmp/barel2tp-ui-\(section.rawValue).png"))
    }
}

@Test @MainActor func closingLastWindowDoesNotQuit() {
    let delegate = AppDelegate()
    #expect(!delegate.applicationShouldTerminateAfterLastWindowClosed(NSApplication.shared))
}

@Test @MainActor func quitBehaviorDependsOnMenuBarIconAndIntent() {
    let delegate = AppDelegate()

    // With the menu bar icon shown, a normal quit request only hides the UI.
    TerminationIntent.isExplicit = false
    #expect(delegate.hidesInsteadOfTerminating(menuBarIconEnabled: true))
    // With the icon hidden there is no other entry point, so the app must really quit.
    #expect(!delegate.hidesInsteadOfTerminating(menuBarIconEnabled: false))

    // Choosing "Quit" in the menu bar quits even while the icon is shown.
    TerminationIntent.isExplicit = true
    #expect(!delegate.hidesInsteadOfTerminating(menuBarIconEnabled: true))

    // Quitting while the VPN is connected asks for confirmation; without a connection it must not.
    TerminationIntent.isSystemInitiated = false
    #expect(delegate.needsQuitConfirmation(hasActiveConnection: true))
    #expect(!delegate.needsQuitConfirmation(hasActiveConnection: false))
    // System shutdown and logout must go through directly, or they would block the system.
    TerminationIntent.isSystemInitiated = true
    #expect(!delegate.needsQuitConfirmation(hasActiveConnection: true))

    TerminationIntent.isExplicit = false
    TerminationIntent.isSystemInitiated = false
}

@Test @MainActor func duplicateQuitRequestsAreIgnoredWhileQuitting() {
    let delegate = AppDelegate()

    // Pressing the shortcut again while the dialog is open must not bypass the confirmation.
    delegate.quitPhase = .confirming
    #expect(delegate.applicationShouldTerminate(NSApplication.shared) == .terminateCancel)

    // Once confirmed and disconnecting, the dialog must not appear again.
    delegate.quitPhase = .shuttingDown
    #expect(delegate.applicationShouldTerminate(NSApplication.shared) == .terminateCancel)
}

@Test @MainActor func advancedOptionsRenderOffscreen() throws {
    var configuration = VPNConfiguration()
    configuration.mtu = 1200
    configuration.hostname = "mac"

    let rootView = Form {
        Section {
            Text("Advanced Options").fontWeight(.medium)
            AdvancedSettings(configuration: .constant(configuration))
        }
    }
    .formStyle(.grouped)
    .toggleStyle(.switch)
    let hostingView = NSHostingView(rootView: rootView)
    hostingView.frame = NSRect(x: 0, y: 0, width: 700, height: 660)
    let window = NSWindow(
        contentRect: hostingView.frame,
        styleMask: [.titled],
        backing: .buffered,
        defer: false
    )
    window.contentView = hostingView
    window.layoutIfNeeded()
    RunLoop.current.run(until: Date().addingTimeInterval(0.15))
    hostingView.layoutSubtreeIfNeeded()

    guard let representation = hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds) else {
        Issue.record("could not create a bitmap for Advanced Options")
        return
    }
    hostingView.cacheDisplay(in: hostingView.bounds, to: representation)
    guard let png = representation.representation(using: .png, properties: [:]) else {
        Issue.record("could not create a PNG for Advanced Options")
        return
    }
    try png.write(to: URL(fileURLWithPath: "/tmp/barel2tp-ui-advanced.png"))
}

@Test func explicitLanguageIgnoresSystemLanguages() {
    let available = ["en", "zh-Hans"]
    #expect(AppLanguage.english.resolvedLocalization(systemLanguages: ["zh-Hans-CN"], available: available) == "en")
    #expect(AppLanguage.simplifiedChinese.resolvedLocalization(systemLanguages: ["en-US"], available: available) == "zh-Hans")
}

@Test func systemLanguageFollowsSystemPreferences() {
    let available = ["en", "zh-Hans"]
    #expect(AppLanguage.system.resolvedLocalization(systemLanguages: ["zh-Hans-CN", "en-US"], available: available) == "zh-Hans")
    #expect(AppLanguage.system.resolvedLocalization(systemLanguages: ["fr-FR"], available: available) == "en")
}

@Test func languagesAreNamedInTheirOwnLanguage() {
    #expect(AppLanguage.english.displayName == "English")
    #expect(AppLanguage.simplifiedChinese.displayName == "简体中文")
}
