import Foundation

/// The last log line when the backend exits is written for developers, with a timestamp, log level
/// and structured fields. This turns it into a sentence the user can act on; the raw record stays
/// in the Log.
struct ConnectionFailure: Equatable {
    /// One sentence describing what happened.
    let summary: String
    /// What to do next; nil when there is no reliable advice.
    let advice: String?

    /// Dialog body: the reason first, then the advice.
    var detail: String {
        guard let advice else { return summary }
        return "\(summary)\n\n\(advice)"
    }

    /// Rules are ordered from most to least specific. For example, "tunnel authentication" must
    /// come before the generic "authentication", or it would be classified as a wrong account
    /// password and send the user to fix the wrong thing.
    ///
    /// The backend log is always in English, and keywords match the backend's error text.
    private static var rules: [(keywords: [String], summary: String, advice: String?)] {
        [
            (
                ["tunnel authentication", "tunnel secret", "hidden"],
                L("The server requires an L2TP tunnel secret."),
                L("Servers that require a tunnel secret are not supported yet. Ask your network administrator how to connect.")
            ),
            (
                ["CHAP", "authentication", "password"],
                L("The server rejected this account."),
                L("Check the username and password in Connection settings (they are case-sensitive). If you changed your password recently, enter it again.")
            ),
            (
                ["failed to resolve", "no IPv4 address", "nodename", "Name or service not known"],
                L("The VPN server could not be found."),
                L("Check the server address in Connection settings and make sure this Mac is online.")
            ),
            (
                ["timed out", "timeout"],
                L("The server did not respond and the connection timed out."),
                L("Make sure the server address and port are correct and that this network can reach the server. Some public networks block UDP port 1701, which L2TP uses.")
            ),
            (
                ["Network is unreachable", "No route to host"],
                L("The network is unreachable; the server can't be reached."),
                L("Check this Mac's network connection, or try again on a different network.")
            ),
            (
                ["Connection refused"],
                L("The server refused the connection."),
                L("Make sure the port is correct, and ask your network administrator whether the service is running.")
            ),
            (
                ["configure interface", "Operation not permitted", "Permission denied", "requires root"],
                L("Couldn't create the VPN network interface: insufficient privileges."),
                L("Connect again and complete administrator authorization in the system dialog.")
            ),
            (
                ["route"],
                L("Couldn't set up subnet routes."),
                L("Check the subnets under Subnets and make sure they don't conflict with this Mac's current network.")
            ),
            (
                ["closed the control tunnel", "closed the PPP session", "closed the L2TP", "STOP_CCN", "CDN"],
                L("The server closed the connection."),
                L("The session may have expired or been limited by the server. Try again later, and contact your network administrator if it keeps failing.")
            ),
        ]
    }

    /// Infers the failure reason from the backend's last log line. An empty line means the backend
    /// left no clue.
    static func describing(logLine rawLine: String) -> ConnectionFailure {
        let line = cleaned(rawLine)
        guard !line.isEmpty else {
            return ConnectionFailure(
                summary: L("The VPN backend quit unexpectedly."),
                advice: L("Try again. If it still fails, send the contents of the Log to your network administrator.")
            )
        }
        for rule in rules where rule.keywords.contains(where: {
            line.localizedCaseInsensitiveContains($0)
        }) {
            return ConnectionFailure(summary: rule.summary, advice: rule.advice)
        }
        return ConnectionFailure(summary: line, advice: L("See the Log for details."))
    }

    /// Strips the timestamp, log level and anyhow prefixes, keeping only the human-readable part.
    static func cleaned(_ source: String) -> String {
        var line = source.trimmingCharacters(in: .whitespaces)
        for pattern in [
            #"^\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s*"#,
            #"^(TRACE|DEBUG|INFO|WARN|ERROR)\s*"#,
            #"^Error:\s*"#,
            #"^Caused by:?\s*"#,
        ] {
            line = line.replacingOccurrences(
                of: pattern,
                with: "",
                options: [.regularExpression, .caseInsensitive]
            )
        }
        return line.trimmingCharacters(in: .whitespaces)
    }
}
