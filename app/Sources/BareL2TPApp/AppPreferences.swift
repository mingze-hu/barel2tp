import Foundation

enum AppPreferenceKeys {
    static let menuBarIconEnabled = "menuBarIconEnabled"

    /// The AppKit side (AppDelegate) reads UserDefaults directly and must agree with the
    /// @AppStorage default.
    static func registerDefaults() {
        UserDefaults.standard.register(defaults: [menuBarIconEnabled: true])
    }

    static var menuBarIconIsEnabled: Bool {
        UserDefaults.standard.bool(forKey: menuBarIconEnabled)
    }
}
