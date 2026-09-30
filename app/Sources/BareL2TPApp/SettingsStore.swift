import Foundation

struct SettingsStore {
    let paths: AppPaths

    func load() throws -> VPNConfiguration {
        let data = try Data(contentsOf: paths.preferences)
        return try JSONDecoder().decode(VPNConfiguration.self, from: data)
    }

    func save(_ configuration: VPNConfiguration) throws {
        try paths.prepare()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(configuration)
        try data.write(to: paths.preferences, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: paths.preferences.path
        )

        try Data(configuration.toml().utf8).write(to: paths.generatedConfig, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: paths.generatedConfig.path
        )
    }
}
