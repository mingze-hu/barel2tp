import SwiftUI

/// Global visual constants. Corner radii, spacing and motion are managed in one place so every page
/// looks consistent.
enum Theme {
    /// Continuous corner (squircle) radii. System controls all use continuous corners, which look
    /// softer than the default ones.
    enum Radius {
        static let chip: CGFloat = 9
        static let control: CGFloat = 12
        static let card: CGFloat = 18
    }

    enum Spacing {
        static let tight: CGFloat = 8
        static let regular: CGFloat = 14
        static let section: CGFloat = 22
        static let page: CGFloat = 30
    }

    /// Maximum width of page content, so lines don't get too long in large windows.
    static let contentWidth: CGFloat = 720

    /// Spring animation used for all state transitions.
    static let transition = Animation.spring(response: 0.42, dampingFraction: 0.84)
}

/// Shorthand for a continuous rounded rectangle.
func squircle(_ radius: CGFloat) -> RoundedRectangle {
    RoundedRectangle(cornerRadius: radius, style: .continuous)
}

extension View {
    /// Card surface: translucent material, hairline border and a soft shadow.
    func cardSurface(radius: CGFloat = Theme.Radius.card) -> some View {
        background(.regularMaterial, in: squircle(radius))
            .overlay {
                squircle(radius)
                    .strokeBorder(.white.opacity(0.06), lineWidth: 1)
                    .blendMode(.plusLighter)
            }
            .overlay {
                squircle(radius).strokeBorder(.separator.opacity(0.5), lineWidth: 1)
            }
            .shadow(color: .black.opacity(0.06), radius: 12, y: 4)
    }
}

extension VPNStatus {
    /// Accent color of the main control. When disconnected it uses the accent color to invite a
    /// click.
    var dialTint: Color {
        switch self {
        case .connected: .green
        case .authorizing, .connecting, .disconnecting: .orange
        case .failed: .red
        case .disconnected: .accentColor
        }
    }

    /// Action label shown in the center of the main control.
    var actionTitle: String {
        switch self {
        case .connected: L("Disconnect")
        case .connecting: L("Connecting")
        case .authorizing: L("Authorizing")
        case .disconnecting: L("Disconnecting")
        case .failed: L("Retry")
        case .disconnected: L("Connect")
        }
    }
}

/// Menu row button: shows a rounded highlight on hover, matching system menu feedback.
struct MenuRowButtonStyle: ButtonStyle {
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background {
                squircle(Theme.Radius.chip)
                    .fill(Color.accentColor)
                    .opacity(configuration.isPressed ? 0.85 : (hovering ? 0.7 : 0))
            }
            .foregroundStyle(hovering ? Color.white : Color.primary)
            .contentShape(squircle(Theme.Radius.chip))
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
    }
}
