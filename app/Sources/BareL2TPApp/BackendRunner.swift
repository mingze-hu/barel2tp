import Darwin
import Foundation

// The Darwin module also exports a flock struct; bind the POSIX function of the same name
// explicitly so Swift does not resolve it wrongly.
@_silgen_name("flock")
private func posixFlock(_ descriptor: CInt, _ operation: CInt) -> CInt

/// Waiting for external commands and reading their pipes are blocking calls and must leave Swift
/// concurrency's cooperative thread pool. That pool is only as large as the number of CPU cores, so
/// a few concurrent commands can exhaust it, and then other async tasks in the process, including
/// the one that issues the cancellation, can no longer get a thread.
private let blockingCommandQueue = DispatchQueue(
    label: "io.github.mingze-hu.barel2tp.command",
    qos: .userInitiated,
    attributes: .concurrent
)

/// Each pipe is read to the end on its own thread, then handed to the waiting side.
private final class PipeOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var storage = Data()

    func store(_ data: Data) {
        lock.lock()
        storage = data
        lock.unlock()
    }

    var data: Data {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

/// Terminates the running external command when the task is cancelled. NSLock only protects the
/// handle and the cancellation flag; the blocking Process wait and pipe reads happen outside the
/// lock.
private final class RunningProcessController: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var isCancelled = false

    /// Checks for cancellation, starts and registers the process under the lock, so a cancellation
    /// cannot land between registering and `Process.run()`: at that point the process is not
    /// running yet, the canceller cannot terminate it, and it would still start normally
    /// afterwards.
    func start(_ process: Process) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !isCancelled else { throw CancellationError() }
        try process.run()
        self.process = process
    }

    func cancel() {
        lock.lock()
        isCancelled = true
        let process = process
        lock.unlock()
        // start only registers the process after run succeeds; terminate is safe even for a process
        // that has just exited.
        process?.terminate()
    }

    func clear() {
        lock.lock()
        process = nil
        lock.unlock()
    }
}

struct BackendRunner: Sendable {
    let paths: AppPaths

    func launch(password: String) async throws {
        try paths.prepare()
        let binary = try findBinary()
        try ensureNoRunningProcess()

        let check = try await Self.run(
            executable: binary,
            arguments: ["--config", paths.generatedConfig.path, "--check"]
        )
        guard check.status == 0 else {
            // The backend has not really started, so don't send the UI to the log for the reason;
            // that log belongs to the previous connection.
            throw BackendError.configurationRejected(check.combinedOutput)
        }

        removeRuntimeFiles()
        let fifoResult = paths.passwordFIFO.path.withCString {
            Darwin.mkfifo($0, mode_t(S_IRUSR | S_IWUSR))
        }
        guard fifoResult == 0 else {
            throw BackendError.system(L("Couldn't create the password pipe: \(String(cString: strerror(errno)))"))
        }

        do {
            let uid = getuid()
            // A state file means the previous run did not finish cleaning up; roll back its
            // recorded routes before connecting.
            let command = privilegedLaunchCommand(
                binary: binary,
                uid: uid,
                cleansLeftovers: hasLeftoverRoutes()
            )
            let script = "do shell script \"\(Self.appleScriptQuote(command))\" with administrator privileges"
            // --daemon only returns once the tunnel is up, and retries across the stages can add up
            // to more than a minute, while AppleScript's default event timeout is only two minutes
            // and would cut off a connection still negotiating.
            let arguments = [
                "-e", "with timeout of 600 seconds",
                "-e", script,
                "-e", "end timeout",
            ]
            // The background shell waits for a writer when it opens the FIFO for reading, so the
            // password must be delivered concurrently with the authorization command.
            let passwordDelivery = Task {
                try await Self.deliverPassword(password, to: paths.passwordFIFO)
            }
            defer { passwordDelivery.cancel() }
            let authorization = try await Self.run(
                executable: URL(fileURLWithPath: "/usr/bin/osascript"),
                arguments: arguments
            )
            guard authorization.status == 0 else {
                throw Self.failure(from: authorization)
            }

            try await passwordDelivery.value
            try? FileManager.default.removeItem(at: paths.passwordFIFO)
        } catch {
            try? FileManager.default.removeItem(at: paths.passwordFIFO)
            throw error
        }
    }

    /// Whether the previous run left routes that were not rolled back. The backend writes the state
    /// file when installing routes and deletes it once cleaned up.
    func hasLeftoverRoutes() -> Bool {
        FileManager.default.fileExists(atPath: paths.state.path)
    }

    /// Rolls back routes left by a previous abnormal exit. Changing the routing table requires
    /// root, so it needs another administrator authorization.
    func cleanupLeftovers() async throws -> String {
        guard !isRunning() else { throw BackendError.alreadyRunning }
        let binary = try findBinary()
        let command = privilegedCleanupCommand(binary: binary)
        let script = "do shell script \"\(Self.appleScriptQuote(command))\" with administrator privileges"
        let result = try await Self.run(
            executable: URL(fileURLWithPath: "/usr/bin/osascript"),
            arguments: ["-e", script]
        )
        guard result.status == 0 else { throw Self.failure(from: result) }
        return result.combinedOutput
    }

    func privilegedCleanupCommand(binary: URL) -> String {
        [
            Self.shellQuote(binary.path),
            "--cleanup",
            "--pid-file", Self.shellQuote(paths.pid.path),
            "--state-file", Self.shellQuote(paths.state.path),
        ].joined(separator: " ")
    }

    func sendDisconnect() async throws {
        for _ in 0..<20 {
            if FileManager.default.fileExists(atPath: paths.controlSocket.path) { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        guard FileManager.default.fileExists(atPath: paths.controlSocket.path) else {
            throw BackendError.system(L("The connection process did not respond to the disconnect request"))
        }
        let socketPath = paths.controlSocket.path
        try await Task.detached(priority: .userInitiated) {
            try Self.sendControlMessage("disconnect", to: socketPath)
        }.value
    }

    /// Whether the backend is still alive.
    ///
    /// `kill(pid, 0)` alone is not enough: the PID file survives a force-kill or power loss, and
    /// the PID is eventually reused by the system. The UI would then show "Connected" forever while
    /// blocking both connecting and cleanup, leaving the user stuck. So the process must also be
    /// confirmed to be the backend itself.
    func isRunning() -> Bool {
        guard let pid = Self.readLockedPID(at: paths.pid) else { return false }
        if Darwin.kill(pid, 0) != 0, errno != EPERM { return false }
        return Self.isBackend(pid: pid)
    }

    /// Trusts the process ID only while the backend still holds an exclusive lock on the PID file.
    /// A stale file left by a crash never makes the UI think the VPN is running, even if the PID
    /// has been reused.
    static func readLockedPID(at url: URL) -> Int32? {
        let descriptor = url.path.withCString {
            Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        if posixFlock(descriptor, LOCK_EX | LOCK_NB) == 0 {
            _ = posixFlock(descriptor, LOCK_UN)
            return nil
        }
        guard errno == EWOULDBLOCK || errno == EAGAIN else { return nil }

        var buffer = [UInt8](repeating: 0, count: 64)
        let length = Darwin.read(descriptor, &buffer, buffer.count)
        guard length > 0 else { return nil }
        let source = String(decoding: buffer.prefix(Int(length)), as: UTF8.self)
        guard let value = Int32(source.trimmingCharacters(in: .whitespacesAndNewlines)),
              value > 1
        else { return nil }
        return value
    }

    /// Backend executable name, used to check whether the process ID in the PID file is the
    /// backend.
    private static let backendName = "barel2tp"

    /// Whether this process ID is the backend itself.
    ///
    /// When the path cannot be read, assume yes: the backend runs as root and `proc_pidpath` cannot
    /// read the path of another user's process anyway. It is safer to assume the backend is alive
    /// than to misjudge it as stopped and start it again.
    static func isBackend(pid: Int32) -> Bool {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return true }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let path = String(decoding: bytes, as: UTF8.self)
        return URL(fileURLWithPath: path).lastPathComponent == backendName
    }

    func readLog(limit: Int = 80_000) -> String {
        guard let data = try? Data(contentsOf: paths.log) else { return "" }
        let bytes = data.count > limit ? data.suffix(limit) : data[...]
        return Self.stripANSI(String(decoding: bytes, as: UTF8.self))
    }

    func cleanupAfterExit() {
        for url in [paths.pid, paths.passwordFIFO, paths.controlSocket] {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func findBinary() throws -> URL {
        if let bundled = Bundle.main.url(forResource: "barel2tp", withExtension: nil),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        if let override = ProcessInfo.processInfo.environment["BAREL2TP_BINARY"] {
            let url = URL(fileURLWithPath: override)
            if FileManager.default.isExecutableFile(atPath: url.path) { return url }
        }
        let development = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("target/release/barel2tp")
        if FileManager.default.isExecutableFile(atPath: development.path) { return development }
        throw BackendError.binaryNotFound
    }

    private func ensureNoRunningProcess() throws {
        if isRunning() {
            throw BackendError.alreadyRunning
        }
    }

    private func removeRuntimeFiles() {
        // Delete the PID file: preventing duplicate starts relies on the backend's own file lock,
        // not on whether this file exists, and keeping it would leave the UI stuck on "Connected"
        // when the PID is reused. The caller has already checked that the backend is not running.
        // The state file is the exception: it records routes a previous abnormal exit did not roll
        // back, and the launch command cleans them up first.
        for url in [paths.pid, paths.log, paths.passwordFIFO, paths.controlSocket] {
            try? FileManager.default.removeItem(at: url)
        }
    }

    /// The backend daemonizes itself: `--daemon` only returns once the tunnel is really up, so the
    /// command's success is the connection's success, and the backend also takes care of the PID
    /// file and log permissions.
    func privilegedLaunchCommand(binary: URL, uid: uid_t, cleansLeftovers: Bool) -> String {
        let executable = Self.shellQuote(binary.path)
        let log = Self.shellQuote(paths.log.path)
        let pid = Self.shellQuote(paths.pid.path)
        let state = Self.shellQuote(paths.state.path)

        // If the previous run was force-killed, its routes are still in the system; roll them back
        // from the record first. A failed cleanup must not block this connection.
        let cleanup = cleansLeftovers
            ? "\(executable) --cleanup --pid-file \(pid) --state-file \(state) >> \(log) 2>&1 || true; "
            : ""
        let launch = [
            executable,
            "--config", Self.shellQuote(paths.generatedConfig.path),
            "--password-stdin",
            "--control-socket", Self.shellQuote(paths.controlSocket.path),
            "--control-uid", String(uid),
            "--daemon",
            "--log-file", log,
            "--pid-file", pid,
            "--state-file", state,
            // The backend runs as root; the UI must be able to read the log and tell whether the
            // backend is alive.
            "--runtime-uid", String(uid),
            "<", Self.shellQuote(paths.passwordFIFO.path),
        ].joined(separator: " ")

        return "umask 077; \(cleanup)\(launch)"
    }

    static func sendControlMessage(_ message: String, to path: String) throws {
        let descriptor = Darwin.socket(AF_UNIX, SOCK_DGRAM, 0)
        guard descriptor >= 0 else {
            throw BackendError.system(
                L("Couldn't create the local control socket: \(String(cString: strerror(errno)))")
            )
        }
        defer { Darwin.close(descriptor) }

        var address = try unixSocketAddress(path: path)
        let payload = Data(message.utf8)
        let sent = payload.withUnsafeBytes { payloadBuffer in
            withUnsafePointer(to: &address) { addressPointer in
                addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    Darwin.sendto(
                        descriptor,
                        payloadBuffer.baseAddress,
                        payloadBuffer.count,
                        0,
                        socketAddress,
                        socklen_t(MemoryLayout<sockaddr_un>.size)
                    )
                }
            }
        }
        guard sent == payload.count else {
            throw BackendError.system(
                L("Couldn't send the disconnect command: \(String(cString: strerror(errno)))")
            )
        }
    }

    static func unixSocketAddress(path: String) throws -> sockaddr_un {
        let pathBytes = Array(path.utf8) + [0]
        var address = sockaddr_un()
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= capacity else {
            throw BackendError.system(L("The local control socket path is too long"))
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: pathBytes)
        }
        return address
    }

    static func stripANSI(_ source: String) -> String {
        source.replacingOccurrences(
            of: "\u{001B}\\[[0-9;]*[A-Za-z]",
            with: "",
            options: .regularExpression
        )
    }

    static func deliverPassword(_ password: String, to fifo: URL) async throws {
        let path = fifo.path
        let payload = Data((password + "\n").utf8)
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(120))

        while true {
            try Task.checkCancellation()
            let descriptor = path.withCString { Darwin.open($0, O_WRONLY | O_NONBLOCK) }
            if descriptor < 0 {
                let errorNumber = errno
                if errorNumber == ENXIO || errorNumber == ENOENT {
                    guard clock.now < deadline else {
                        throw BackendError.system(L("Timed out waiting for the authorized process to read the password"))
                    }
                    try await Task.sleep(for: .milliseconds(50))
                    continue
                }
                throw BackendError.system(
                    L("Couldn't open the password pipe: \(String(cString: strerror(errorNumber)))")
                )
            }
            defer { Darwin.close(descriptor) }
            try payload.withUnsafeBytes { rawBuffer in
                guard let base = rawBuffer.baseAddress else { return }
                var offset = 0
                while offset < rawBuffer.count {
                    let written = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                    guard written > 0 else {
                        throw BackendError.system(L("Couldn't write to the password pipe: \(String(cString: strerror(errno)))"))
                    }
                    offset += written
                }
            }
            return
        }
    }

    static func run(
        executable: URL,
        arguments: [String],
        input: Data? = nil
    ) async throws -> CommandResult {
        let controller = RunningProcessController()
        return try await withTaskCancellationHandler {
            let result = try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<CommandResult, Error>) in
                blockingCommandQueue.async {
                    continuation.resume(with: Result {
                        try execute(
                            executable: executable,
                            arguments: arguments,
                            input: input,
                            controller: controller
                        )
                    })
                }
            }
            try Task.checkCancellation()
            return result
        } onCancel: {
            controller.cancel()
        }
    }

    /// Runs a command from start to finish, blocking; the caller is responsible for putting it on
    /// `blockingCommandQueue`.
    private static func execute(
        executable: URL,
        arguments: [String],
        input: Data?,
        controller: RunningProcessController
    ) throws -> CommandResult {
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        let standardInput = input.map { _ in Pipe() }
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = error
        process.standardInput = standardInput
        try controller.start(process)
        defer { controller.clear() }

        // Both pipes must be drained concurrently before waiting for the process to exit; a full
        // pipe blocks the child, and calling waitUntilExit before reading would deadlock forever.
        let stdout = PipeOutput()
        let stderr = PipeOutput()
        let readers = DispatchGroup()
        blockingCommandQueue.async(group: readers) {
            stdout.store(output.fileHandleForReading.readDataToEndOfFile())
        }
        blockingCommandQueue.async(group: readers) {
            stderr.store(error.fileHandleForReading.readDataToEndOfFile())
        }
        if let input, let standardInput {
            try standardInput.fileHandleForWriting.write(contentsOf: input)
            try standardInput.fileHandleForWriting.close()
        }
        process.waitUntilExit()
        readers.wait()
        return CommandResult(
            status: process.terminationStatus,
            stdout: String(decoding: stdout.data, as: UTF8.self),
            stderr: String(decoding: stderr.data, as: UTF8.self)
        )
    }

    /// A cancelled authorization dialog and a genuinely failed command are two different things to
    /// the user.
    ///
    /// Only AppleScript's own cancellation error number (-128) counts: `--daemon` keeps the command
    /// running until the tunnel is up, and on failure the output includes the backend's
    /// diagnostics. Scanning the whole output for words like "cancel" would quietly swallow a real
    /// failure as a user cancellation.
    static func failure(from result: CommandResult) -> BackendError {
        if result.stderr.range(
            of: #"execution error:.*\(-128\)"#,
            options: [.regularExpression]
        ) != nil {
            return .authorizationCancelled
        }
        return .commandFailed(result.combinedOutput)
    }

    private static func shellQuote(_ source: String) -> String {
        "'" + source.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static func appleScriptQuote(_ source: String) -> String {
        source
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}

struct CommandResult: Sendable {
    let status: Int32
    let stdout: String
    let stderr: String

    var combinedOutput: String {
        [stdout, stderr]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
    }
}

enum BackendError: LocalizedError {
    case binaryNotFound
    case alreadyRunning
    case authorizationCancelled
    /// `--check` rejected the configuration. The backend has not started, so the log has no trace
    /// of this connection.
    case configurationRejected(String)
    /// The authorization command failed. The backend has already run once, so only the log has the
    /// real reason.
    case commandFailed(String)
    case system(String)

    var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            L("The barel2tp backend was not found. Build the app with the project's build script.")
        case .alreadyRunning:
            L("The VPN backend is already running")
        case .authorizationCancelled:
            L("Administrator authorization was cancelled")
        case let .configurationRejected(message):
            message.isEmpty ? L("The configuration check failed") : message
        case let .commandFailed(message):
            message.isEmpty ? L("The backend command failed") : message
        case let .system(message):
            message
        }
    }

    /// Whether the backend has already run once. Only then does it make sense to look for the
    /// failure reason in the log; otherwise the log belongs to the previous connection and would
    /// give an unrelated answer.
    var ranBackend: Bool {
        if case .commandFailed = self { return true }
        return false
    }
}
