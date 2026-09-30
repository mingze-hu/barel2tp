import SwiftUI

/// Main control of the overview: a clickable ring that both shows the status and toggles the
/// connection.
struct ConnectionDial: View {
    let status: VPNStatus
    /// Action label in the center of the ring. Follows the status by default; replaced with a setup
    /// prompt when required fields are missing.
    var actionTitle: String?
    let action: () -> Void

    private var title: String { actionTitle ?? status.actionTitle }

    private let diameter: CGFloat = 168
    private let ringWidth: CGFloat = 12

    @State private var hovering = false
    @State private var breathing = false

    var body: some View {
        Button(action: action) {
            ZStack {
                glow
                track
                progress
                core
            }
            .frame(width: diameter, height: diameter)
            .scaleEffect(hovering ? 1.02 : 1)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(status == .disconnecting)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.18), value: hovering)
        .animation(Theme.transition, value: status)
        .onAppear {
            withAnimation(.easeInOut(duration: 2.4).repeatForever(autoreverses: true)) {
                breathing = true
            }
        }
        .accessibilityLabel("\(title) VPN")
        .accessibilityValue(status.title)
    }

    /// Soft glow outside the ring that gently pulses.
    private var glow: some View {
        Circle()
            .fill(status.dialTint)
            .blur(radius: 34)
            .opacity(breathing ? 0.26 : 0.16)
            .scaleEffect(breathing ? 1.04 : 0.96)
    }

    /// Background track.
    private var track: some View {
        Circle()
            .strokeBorder(.quaternary, lineWidth: ringWidth)
    }

    /// Progress ring: a spinning arc while busy, a full gradient ring when connected.
    @ViewBuilder
    private var progress: some View {
        if status.isBusy {
            TimelineView(.animation) { context in
                let cycle = 1.5
                let phase = context.date.timeIntervalSinceReferenceDate
                    .truncatingRemainder(dividingBy: cycle) / cycle
                Circle()
                    .trim(from: 0, to: 0.22)
                    .stroke(
                        status.dialTint.gradient,
                        style: StrokeStyle(lineWidth: ringWidth, lineCap: .round)
                    )
                    .rotationEffect(.degrees(phase * 360 - 90))
                    .padding(ringWidth / 2)
            }
        } else if status == .connected {
            Circle()
                .stroke(
                    AngularGradient(
                        colors: [
                            status.dialTint.opacity(0.35),
                            status.dialTint,
                            status.dialTint.opacity(0.35),
                        ],
                        center: .center
                    ),
                    style: StrokeStyle(lineWidth: ringWidth, lineCap: .round)
                )
                .padding(ringWidth / 2)
        } else {
            Circle()
                .stroke(status.dialTint.opacity(0.35), lineWidth: ringWidth)
                .padding(ringWidth / 2)
        }
    }

    /// Center area: material background, symbol and action label.
    private var core: some View {
        ZStack {
            Circle()
                .fill(.regularMaterial)
                .overlay {
                    Circle().fill(status.dialTint.opacity(hovering ? 0.14 : 0.08))
                }
                .overlay {
                    Circle().strokeBorder(.separator.opacity(0.4), lineWidth: 1)
                }

            VStack(spacing: 7) {
                Image(systemName: status.symbol)
                    .font(.system(size: 34, weight: .medium))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(status.dialTint)
                Text(title)
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(ringWidth + 8)
    }
}
