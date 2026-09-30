import Foundation

/// Looks up a UI string in the current language.
///
/// The key is the English source text; the Chinese translation lives in
/// `Resources/zh-Hans.lproj/Localizable.strings`, and plural rules in the `Localizable.stringsdict`
/// files. When no translation exists the English text is shown. SwiftUI literals such as
/// `Text("…")` and `Button("…")` look themselves up; only strings passed around as `String` need to
/// go through here.
func L(_ key: String.LocalizationValue) -> String {
    String(localized: key)
}

extension Array where Element == String {
    /// Joins several items into one phrase using the system locale, for example "Server, Username,
    /// and Password".
    var localizedList: String {
        formatted(.list(type: .and))
    }
}
