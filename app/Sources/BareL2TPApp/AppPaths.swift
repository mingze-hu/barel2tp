import Foundation

struct AppPaths: Sendable {
    let supportDirectory: URL

    init(fileManager: FileManager = .default) {
        let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        supportDirectory = base.appendingPathComponent("BareL2TP", isDirectory: true)
    }

    var preferences: URL { supportDirectory.appendingPathComponent("settings.json") }
    var generatedConfig: URL { supportDirectory.appendingPathComponent("config.toml") }
    var log: URL { supportDirectory.appendingPathComponent("barel2tp.log") }
    var pid: URL { supportDirectory.appendingPathComponent("barel2tp.pid") }
    /// Records which routes the backend installed; used for rollback when the backend is
    /// force-killed.
    var state: URL { supportDirectory.appendingPathComponent("barel2tp.state") }
    var passwordFIFO: URL { supportDirectory.appendingPathComponent("password.fifo") }
    var controlSocket: URL { supportDirectory.appendingPathComponent("control.sock") }

    func prepare() throws {
        try FileManager.default.createDirectory(
            at: supportDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: supportDirectory.path
        )
    }
}
