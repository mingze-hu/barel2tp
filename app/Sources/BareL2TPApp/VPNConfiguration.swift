import Foundation

struct VPNConfiguration: Codable, Equatable, Sendable {
    var server = ""
    var port = 1701
    var username = ""
    var routesText = ""
    var mtu = 1400
    var timeoutSeconds = 3
    var retries = 5
    var helloIntervalSeconds = 30
    var requestDNS = false
    var localBind = ""
    var localPort = 0
    var hostname = ""

    var routes: [String] {
        routesText
            .components(separatedBy: CharacterSet(charactersIn: ",\n"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    /// Route lines with invalid syntax, flagged in the UI right away instead of failing only when
    /// the user clicks Connect.
    var invalidRoutes: [String] {
        routes.filter { !Self.isIPv4CIDR($0) }
    }

    /// Whether all advanced parameters are still at their defaults. Server, account and routes are
    /// user data and do not count.
    var usesDefaultAdvancedSettings: Bool {
        var restored = self
        restored.resetAdvancedSettings()
        return restored == self
    }

    /// Restores the advanced parameters to their defaults.
    mutating func resetAdvancedSettings() {
        let defaults = VPNConfiguration()
        mtu = defaults.mtu
        timeoutSeconds = defaults.timeoutSeconds
        retries = defaults.retries
        helloIntervalSeconds = defaults.helloIntervalSeconds
        requestDNS = defaults.requestDNS
        localBind = defaults.localBind
        localPort = defaults.localPort
        hostname = defaults.hostname
    }

    func validate() throws {
        if server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw ConfigurationError.invalid(L("Enter the server address in Connection settings first"))
        }
        if username.isEmpty {
            throw ConfigurationError.invalid(L("Enter the username in Connection settings first"))
        }
        guard (1...65_535).contains(port) else {
            throw ConfigurationError.invalid(L("The server port must be a number from 1 to 65535, usually 1701"))
        }
        guard (576...1500).contains(mtu) else {
            throw ConfigurationError.invalid(L("MTU must be a number from 576 to 1500; the default is 1400"))
        }
        guard timeoutSeconds > 0, retries > 0, helloIntervalSeconds > 0 else {
            throw ConfigurationError.invalid(L("Connection timeout, retries and keepalive interval must all be greater than 0"))
        }
        guard (0...65_535).contains(localPort) else {
            throw ConfigurationError.invalid(L("The local port must be a number from 0 to 65535; 0 means assigned automatically"))
        }
        if !localBind.isEmpty, !Self.isIPv4(localBind) {
            throw ConfigurationError.invalid(L("The local bind address is not a valid IPv4 address; leave it empty to choose automatically"))
        }
        for route in routes where !Self.isIPv4CIDR(route) {
            throw ConfigurationError.invalid(L("Subnet “\(route)” is invalid; use the form 10.20.0.0/16"))
        }
    }

    func toml() -> String {
        var lines = [
            "server = \(Self.quoted(server.trimmingCharacters(in: .whitespacesAndNewlines)))",
            "port = \(port)",
            "username = \(Self.quoted(username))",
            "",
            "routes = [",
        ]
        lines.append(contentsOf: routes.map { "  \(Self.quoted($0))," })
        lines.append(contentsOf: [
            "]",
            "",
            "mtu = \(mtu)",
            "timeout_seconds = \(timeoutSeconds)",
            "retries = \(retries)",
            "hello_interval_seconds = \(helloIntervalSeconds)",
            "request_dns = \(requestDNS)",
            "local_port = \(localPort)",
        ])
        if !localBind.isEmpty {
            lines.append("local_bind = \(Self.quoted(localBind))")
        }
        if !hostname.isEmpty {
            lines.append("hostname = \(Self.quoted(hostname))")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private static func isIPv4(_ source: String) -> Bool {
        let octets = source.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { octet in
            guard !octet.isEmpty, octet.allSatisfy(\.isNumber), let value = Int(octet) else {
                return false
            }
            return (0...255).contains(value)
        }
    }

    private static func isIPv4CIDR(_ source: String) -> Bool {
        let parts = source.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, isIPv4(String(parts[0])), let prefix = Int(parts[1]) else {
            return false
        }
        return (0...32).contains(prefix)
    }

    private static func quoted(_ value: String) -> String {
        var escaped = ""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x08: escaped += "\\b"
            case 0x09: escaped += "\\t"
            case 0x0A: escaped += "\\n"
            case 0x0C: escaped += "\\f"
            case 0x0D: escaped += "\\r"
            case 0x22: escaped += "\\\""
            case 0x5C: escaped += "\\\\"
            default: escaped.unicodeScalars.append(scalar)
            }
        }
        return "\"\(escaped)\""
    }
}

enum ConfigurationError: LocalizedError {
    case invalid(String)

    var errorDescription: String? {
        switch self {
        case let .invalid(message): message
        }
    }
}
