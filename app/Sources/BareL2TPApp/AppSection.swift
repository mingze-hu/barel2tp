import SwiftUI

/// Sections of the main window. Menu bar actions need to take the user to a specific page, so this
/// is no longer private to ContentView.
enum AppSection: String, CaseIterable, Identifiable {
    case overview
    case account
    case routes
    case general
    case diagnostics

    var id: Self { self }

    /// Name shared by the sidebar and the window title. The sidebar is already grouped into "VPN"
    /// and "App", so VPN is not repeated here.
    var title: String {
        switch self {
        case .overview: L("Overview")
        case .account: L("Connection")
        case .routes: L("Subnets")
        case .general: L("General")
        case .diagnostics: L("Log")
        }
    }

    var symbol: String {
        switch self {
        case .overview: "shield.lefthalf.filled"
        case .account: "person.badge.key"
        case .routes: "point.3.connected.trianglepath.dotted"
        case .general: "gearshape"
        case .diagnostics: "waveform.path.ecg"
        }
    }

    /// Background color of the sidebar icon, following the colorful icon style of System Settings.
    var tint: Color {
        switch self {
        case .overview: .blue
        case .account: .indigo
        case .routes: .purple
        case .general: .gray
        case .diagnostics: .teal
        }
    }
}
