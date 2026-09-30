import Foundation

/// The UI language chosen in General settings.
///
/// The choice is stored the same way as the per-app language in System Settings: as
/// `AppleLanguages` in the app's own preferences domain. Bundle lookups, SwiftUI, AppKit alerts and
/// system formatters all read it once at launch, so a change only takes effect after a relaunch.
enum AppLanguage: String, CaseIterable, Identifiable {
    case system
    case english = "en"
    case simplifiedChinese = "zh-Hans"

    var id: Self { self }

    private static let preferenceKey = "AppleLanguages"

    /// Name shown in the picker. Languages are named in their own language so that someone who
    /// cannot read the current UI can still find theirs.
    var displayName: String {
        switch self {
        case .system:
            L("System Default")
        case .english, .simplifiedChinese:
            Locale(identifier: rawValue).localizedString(forIdentifier: rawValue) ?? rawValue
        }
    }

    /// The saved choice. Only the app's own domain is read: the global `AppleLanguages` is the
    /// system language, which is what "System Default" means.
    static var saved: AppLanguage {
        guard let identifier = Bundle.main.bundleIdentifier,
              let domain = UserDefaults.standard.persistentDomain(forName: identifier),
              let languages = domain[preferenceKey] as? [String],
              let first = languages.first
        else { return .system }
        let resolved = Bundle.preferredLocalizations(
            from: allCases.filter { $0 != .system }.map(\.rawValue),
            forPreferences: [first]
        ).first
        return resolved.flatMap(AppLanguage.init(rawValue:)) ?? .system
    }

    static func save(_ language: AppLanguage) {
        if language == .system {
            UserDefaults.standard.removeObject(forKey: preferenceKey)
        } else {
            UserDefaults.standard.set([language.rawValue], forKey: preferenceKey)
        }
    }

    /// The localization this choice will use after the next launch, among those the app ships.
    func resolvedLocalization(
        systemLanguages: [String] = AppLanguage.systemLanguages,
        available: [String] = Bundle.main.localizations
    ) -> String? {
        let preferences = self == .system ? systemLanguages : [rawValue]
        return Bundle.preferredLocalizations(from: available, forPreferences: preferences).first
    }

    /// Whether this choice would show a different language from the one in use right now.
    var needsRelaunch: Bool {
        resolvedLocalization() != Bundle.main.preferredLocalizations.first
    }

    /// The user's system-wide language list. `Locale.preferredLanguages` cannot be used: it
    /// includes the app's own override and is fixed at launch.
    static var systemLanguages: [String] {
        CFPreferencesCopyValue(
            preferenceKey as CFString,
            kCFPreferencesAnyApplication,
            kCFPreferencesCurrentUser,
            kCFPreferencesAnyHost
        ) as? [String] ?? Locale.preferredLanguages
    }

    /// Relaunching only works from an app bundle; `swift run` starts a bare executable.
    static var canRelaunch: Bool {
        Bundle.main.bundleURL.pathExtension == "app"
    }
}
