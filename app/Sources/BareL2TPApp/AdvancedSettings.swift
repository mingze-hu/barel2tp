import SwiftUI

/// Advanced parameters. They share a card with the "Advanced Options" header row and only appear
/// when expanded; a separate group would look like a peer of the settings above rather than their
/// collapsed part.
struct AdvancedSettings: View {
    @Binding var configuration: VPNConfiguration

    var body: some View {
        Group {
            groupLabel(L("Tunnel"))
            numberField("MTU", value: $configuration.mtu, hint: L("Lower this if web pages fail to load or transfers stall"))
            numberField(L("Connection timeout"), value: $configuration.timeoutSeconds, unit: L("s"))
            numberField(L("Retries"), value: $configuration.retries)
            numberField(L("Keepalive interval"), value: $configuration.helloIntervalSeconds, unit: L("s"))

            groupLabel(L("This Mac"))
            textField(L("Local interface address"), text: $configuration.localBind, prompt: L("Automatic"))
            numberField(L("Local port"), value: $configuration.localPort, hint: L("0 means assigned automatically"))
            textField(L("Client name"), text: $configuration.hostname, prompt: L("Use this Mac's name"))

            groupLabel("DNS")
            Toggle(isOn: $configuration.requestDNS) {
                // The "logged only" behavior cannot be guessed from the field name, so it must be
                // spelled out.
                fieldLabel(L("Request DNS from server"), hint: L("Only logged; system DNS settings are not changed"))
            }
            .padding(.vertical, 3)

            Button("Restore Defaults") { configuration.resetAdvancedSettings() }
                .frame(maxWidth: .infinity, alignment: .center)
                .disabled(configuration.usesDefaultAdvancedSettings)
                .padding(.vertical, 3)
        }
    }

    /// Small heading inside the card. The separator below is hidden so it reads as one group with
    /// the fields that follow.
    private func groupLabel(_ title: String) -> some View {
        Text(title)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.top, 8)
            .listRowSeparator(.hidden, edges: .bottom)
    }

    // MARK: - Fields

    /// Field label, with an extra line of explanation when needed. Most fields are clear from their
    /// name and placeholder; only those whose behavior is not obvious get a hint.
    private func fieldLabel(_ title: String, hint: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            if let hint {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func numberField(
        _ title: String,
        value: Binding<Int>,
        unit: String? = nil,
        hint: String? = nil
    ) -> some View {
        LabeledContent {
            HStack(spacing: 6) {
                TextField(title, value: value, format: .number.grouping(.never))
                    .labelsHidden()
                    .frame(width: 90)
                if let unit {
                    Text(unit).foregroundStyle(.secondary)
                }
            }
        } label: {
            fieldLabel(title, hint: hint)
        }
        .padding(.vertical, 3)
    }

    private func textField(
        _ title: String,
        text: Binding<String>,
        prompt: String,
        hint: String? = nil
    ) -> some View {
        LabeledContent {
            TextField(title, text: text, prompt: Text(prompt))
                .labelsHidden()
        } label: {
            fieldLabel(title, hint: hint)
        }
        .padding(.vertical, 3)
    }
}
