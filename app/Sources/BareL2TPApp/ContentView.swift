import AppKit
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @AppStorage(AppPreferenceKeys.menuBarIconEnabled) private var menuBarIconEnabled = true
    @State private var showsPassword = false
    @State private var showsAdvanced = false
    @State private var language = AppLanguage.saved

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
        }
        .frame(minWidth: 820, minHeight: 620)
        .alert(
            model.presentedError?.title ?? "",
            isPresented: errorAlertBinding,
            presenting: model.presentedError
        ) { error in
            if error.showsLogShortcut {
                Button("View Log") { model.section = .diagnostics }
            }
            Button("OK", role: .cancel) {}
        } message: { error in
            Text(error.message)
        }
        .onChange(of: model.configuration) { _ in
            model.scheduleConfigurationSave()
        }
        .task { model.start() }
        .task(id: model.requestsMenuBarIconHide) {
            await hideMenuBarIconShowingSwitch()
        }
    }

    private var errorAlertBinding: Binding<Bool> {
        Binding(
            get: { model.presentedError != nil },
            set: { if !$0 { model.presentedError = nil } }
        )
    }

    /// Handles "Hide Menu Bar Icon" from the menu bar: bring the switch into view first and then
    /// turn it off, so the user sees what turned the icon off and where to turn it back on.
    ///
    /// Uses task(id:) rather than onChange: the request is often sent before the main window
    /// exists, and onChange would miss that change.
    private func hideMenuBarIconShowingSwitch() async {
        guard model.requestsMenuBarIconHide else { return }
        // Wait until the window is visible so the user can see the switch is still on.
        try? await Task.sleep(for: .milliseconds(550))
        guard !Task.isCancelled else { return }
        withAnimation(Theme.transition) {
            menuBarIconEnabled = false
        }
        model.requestsMenuBarIconHide = false
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $model.section) {
            Section("VPN") {
                navigationRow(.overview)
                navigationRow(.account)
                navigationRow(.routes)
            }
            Section("App") {
                navigationRow(.general)
                navigationRow(.diagnostics)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .top, spacing: 0) { brandHeader }
        .safeAreaInset(edge: .bottom, spacing: 0) { sidebarFooter }
        .navigationSplitViewColumnWidth(min: 206, ideal: 226, max: 260)
    }

    private var brandHeader: some View {
        HStack(spacing: 10) {
            AppGlyph(size: 30)
            VStack(alignment: .leading, spacing: 0) {
                Text("BareL2TP")
                    .font(.system(size: 13, weight: .semibold))
                Text("Connect to a remote network")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.top, 12)
        .padding(.bottom, 10)
    }

    private var sidebarFooter: some View {
        HStack(spacing: 7) {
            StatusDot(color: model.status.color, animated: model.status.isBusy)
            Text(model.status.title)
                .font(.system(size: 11, weight: .medium))
                .lineLimit(1)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .background(.quaternary.opacity(0.6), in: squircle(Theme.Radius.chip))
        .padding(10)
        .animation(Theme.transition, value: model.status)
    }

    private func navigationRow(_ section: AppSection) -> some View {
        Label {
            Text(section.title)
        } icon: {
            squircle(5.5)
                .fill(section.tint.gradient)
                .frame(width: 19, height: 19)
                .overlay {
                    Image(systemName: section.symbol)
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.white)
                }
        }
        .tag(section)
    }

    // MARK: - Detail

    @ViewBuilder
    private var detail: some View {
        ZStack {
            DetailBackground(color: model.status.dialTint)
            switch model.section {
            case .overview: overviewPage
            case .account: accountPage
            case .routes: routesPage
            case .general: generalPage
            case .diagnostics: diagnosticsPage
            }
        }
        .navigationTitle(model.section.title)
    }

    // MARK: - Overview

    private var overviewPage: some View {
        ScrollView {
            VStack(spacing: Theme.Spacing.section) {
                heroCard
                metricsRow
                summaryCard
                securityNote
            }
            .frame(maxWidth: Theme.contentWidth)
            .padding(Theme.Spacing.page)
            .frame(maxWidth: .infinity)
        }
        .animation(Theme.transition, value: model.status)
    }

    private var heroCard: some View {
        VStack(spacing: 18) {
            ConnectionDial(status: model.status, actionTitle: dialActionTitle) { toggleConnection() }
                .padding(.top, 4)

            VStack(spacing: 6) {
                Text(overviewTitle)
                    .font(.system(size: 22, weight: .semibold, design: .rounded))
                Text(connectionDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: 440)

            if let since = model.connectedSince, model.status == .connected {
                UptimeLabel(since: since)
            }

            heroActions
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 30)
        .padding(.horizontal, 24)
        .cardSurface()
    }

    /// Secondary action below the ring: each state keeps only the one thing the user most likely
    /// wants to do next.
    @ViewBuilder
    private var heroActions: some View {
        switch model.status {
        case .connecting, .authorizing:
            Button("Cancel Connection") { model.disconnect() }
                .buttonStyle(.link)
                .font(.callout)
        case .failed:
            HStack(spacing: 10) {
                Button("Reconnect") { model.connect() }
                    .buttonStyle(.borderedProminent)
                Button("View Log") { model.section = .diagnostics }
            }
        case .disconnected where !model.isConfigured:
            Button("Go to Connection Settings") { model.section = .account }
                .buttonStyle(.borderedProminent)
        default:
            EmptyView()
        }
    }

    private var metricsRow: some View {
        HStack(spacing: 12) {
            MetricCard(
                title: L("Server"),
                value: model.configuration.server.isEmpty ? L("Not set") : model.configuration.server,
                symbol: "server.rack",
                color: .blue
            )
            MetricCard(
                title: L("Account"),
                value: model.configuration.username.isEmpty ? L("Not set") : model.configuration.username,
                symbol: "person.crop.circle",
                color: .indigo
            )
            MetricCard(
                title: L("Subnets"),
                value: model.configuration.routes.isEmpty
                    ? L("None")
                    : "\(model.configuration.routes.count)",
                symbol: "arrow.triangle.branch",
                color: .purple
            )
        }
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 0) {
            CardHeader(title: L("Connection Details"), symbol: "checklist")
            SummaryRow(symbol: "network", title: L("Server and port"), value: serverEndpoint)
            Divider().padding(.leading, 46)
            SummaryRow(symbol: "key", title: L("Password"), value: passwordSummary)
            Divider().padding(.leading, 46)
            SummaryRow(
                symbol: "globe",
                title: "DNS",
                value: model.configuration.requestDNS ? L("Requested from server (logged only)") : L("Use system settings")
            )
            Divider().padding(.leading, 46)
            SummaryRow(symbol: "shippingbox", title: "MTU", value: "\(model.configuration.mtu)")
        }
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface()
    }

    private var securityNote: some View {
        InlineNotice(
            symbol: "exclamationmark.shield.fill",
            tint: .orange,
            title: L("This tunnel is not encrypted"),
            detail: L("L2TP does not encrypt tunnel traffic. Use it only on trusted networks.")
        )
    }

    // MARK: - Connection

    private var accountPage: some View {
        Form {
            Section {
                TextField(
                    L("Server address"),
                    text: $model.configuration.server,
                    prompt: Text("vpn.example.com or an IP address")
                )
                TextField("Port", value: $model.configuration.port, format: .number.grouping(.never))
            } header: {
                Text("Server")
            }

            Section {
                TextField("Username", text: $model.configuration.username, prompt: Text("Employee ID or domain account"))
                passwordField
                Toggle("Remember password", isOn: $model.rememberPassword)
            } header: {
                Text("Account")
            } footer: {
                if model.rememberPassword {
                    footnote(L("The password is stored in the macOS Keychain on this Mac. It is never written to the configuration file or the log."))
                }
            }

            Section {
                advancedDisclosureRow
                if showsAdvanced {
                    AdvancedSettings(configuration: $model.configuration)
                }
            }
        }
        .formStyle(.grouped)
        .toggleStyle(.switch)
        .scrollContentBackground(.hidden)
    }

    /// The whole row is the click target, since the system disclosure triangle is too small to hit
    /// comfortably. The chevron rotates with the expanded state.
    private var advancedDisclosureRow: some View {
        Button {
            withAnimation(Theme.transition) { showsAdvanced.toggle() }
        } label: {
            HStack(spacing: 0) {
                Text("Advanced Options").fontWeight(.medium)
                Spacer(minLength: 12)
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(showsAdvanced ? 90 : 0))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.vertical, 3)
    }

    private var passwordField: some View {
        LabeledContent("Password") {
            HStack(spacing: 6) {
                Group {
                    if showsPassword {
                        TextField("Password", text: $model.password)
                    } else {
                        SecureField("Password", text: $model.password)
                    }
                }
                .labelsHidden()

                Button {
                    showsPassword.toggle()
                } label: {
                    Image(systemName: showsPassword ? "eye.slash" : "eye")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help(showsPassword ? L("Hide password") : L("Show password"))
            }
        }
    }

    // MARK: - Subnets

    private var routesPage: some View {
        Form {
            Section {
                routesEditor
                if !model.configuration.invalidRoutes.isEmpty {
                    InlineNotice(
                        symbol: "exclamationmark.triangle.fill",
                        tint: .orange,
                        title: L("\(model.configuration.invalidRoutes.count) lines are invalid"),
                        detail: L("\(model.configuration.invalidRoutes.localizedList). Use the form 10.20.0.0/16.")
                    )
                    .padding(.vertical, 4)
                }
            } header: {
                Text("Subnets routed through the VPN")
            } footer: {
                HStack(alignment: .top) {
                    footnote(L("One IPv4 subnet per line. Only traffic to these subnets goes through the VPN."))
                    Spacer(minLength: 12)
                    Text("\(model.configuration.routes.count) subnets")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }

            if !model.configuration.routes.isEmpty {
                Section("Reachable once connected") {
                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 170), spacing: 8)],
                        alignment: .leading,
                        spacing: 8
                    ) {
                        ForEach(model.configuration.routes, id: \.self) { route in
                            RouteChip(route: route, isValid: !model.configuration.invalidRoutes.contains(route))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .animation(Theme.transition, value: model.configuration.routes)
    }

    private var routesEditor: some View {
        ZStack(alignment: .topLeading) {
            TextEditor(text: $model.configuration.routesText)
                .font(.system(size: 12.5, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(8)
                .frame(minHeight: 158)

            if model.configuration.routesText.isEmpty {
                Text(verbatim: "10.20.0.0/16\n172.20.8.0/21")
                    .font(.system(size: 12.5, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .padding(.horizontal, 13)
                    .padding(.vertical, 16)
                    .allowsHitTesting(false)
            }
        }
        .background(Color(nsColor: .textBackgroundColor), in: squircle(Theme.Radius.chip))
        .overlay {
            squircle(Theme.Radius.chip).strokeBorder(.separator.opacity(0.7), lineWidth: 1)
        }
        .padding(.vertical, 4)
    }

    // MARK: - General

    private var generalPage: some View {
        Form {
            Section {
                Toggle("Show menu bar icon", isOn: $menuBarIconEnabled)
            } header: {
                Text("Menu Bar")
            } footer: {
                // Neither closing the window nor ⌘Q quits, which is impossible to tell from the UI,
                // so it is explained next to the switch.
                footnote(
                    menuBarIconEnabled
                        ? L("Closing the window or pressing ⌘Q only hides the app in the menu bar and keeps the VPN connected. To quit, choose “Quit BareL2TP” from the menu bar icon.")
                        : L("With the icon hidden, ⌘Q quits the app and disconnects the VPN.")
                )
            }

            Section {
                Picker("Language", selection: $language) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(language.displayName).tag(language)
                    }
                }
                .onChange(of: language) { AppLanguage.save($0) }
                if language.needsRelaunch, AppLanguage.canRelaunch {
                    LabeledContent("Relaunch to switch the language") {
                        Button("Relaunch Now") { TerminationIntent.relaunch() }
                    }
                }
            } header: {
                Text("Language")
            } footer: {
                if language.needsRelaunch {
                    footnote(
                        model.status.canDisconnect || model.status.isBusy
                            ? L("The new language takes effect after BareL2TP relaunches. Relaunching disconnects the VPN.")
                            : L("The new language takes effect after BareL2TP relaunches.")
                    )
                }
            }

            Section {
                LabeledContent("Leftover routes") {
                    if model.isCleaningLeftovers {
                        ProgressView().controlSize(.small)
                    } else {
                        Button("Clean Up") { model.cleanupLeftovers() }
                            .disabled(!model.canCleanupLeftovers)
                    }
                }
            } header: {
                Text("Maintenance")
            } footer: {
                footnote(leftoverRoutesHint)
            }

            Section("About") {
                LabeledContent("Version", value: appVersion)
                LabeledContent("Configuration and log") {
                    Button("Show in Finder") { model.revealSupportFolder() }
                }
            }
        }
        .formStyle(.grouped)
        .toggleStyle(.switch)
        .scrollContentBackground(.hidden)
        // The backend may have been force-killed elsewhere, so check again every time this page
        // appears.
        .onAppear { model.refreshLeftoverRoutes() }
    }

    /// A normal disconnect restores routes by itself and only a forced termination leaves anything
    /// behind, so explain when this button is actually useful.
    private var leftoverRoutesHint: String {
        if !model.hasLeftoverRoutes {
            return L("The routing table is clean. Routes are only left behind if the backend is force-quit; this button becomes available when that happens.")
        }
        if model.status.canDisconnect || model.status.isBusy {
            return L("The previous connection left routes behind. Disconnect first to clean them up.")
        }
        return L("The previous connection was force-quit and some routes were not restored. Cleaning up requires administrator authorization.")
    }

    private var appVersion: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? L("Development")
        guard let build = info?["CFBundleVersion"] as? String else { return short }
        return L("\(short) (\(build))")
    }

    // MARK: - Log

    private var diagnosticsPage: some View {
        VStack(spacing: 14) {
            HStack(spacing: 10) {
                Text("A complete record of the connection. Send it to your network administrator if something goes wrong.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    copyLog()
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .disabled(model.logText.isEmpty)
                Button {
                    model.revealSupportFolder()
                } label: {
                    Label("Show File", systemImage: "folder")
                }
                Button(role: .destructive) {
                    model.clearLog()
                } label: {
                    Label("Clear", systemImage: "trash")
                }
                .disabled(model.status.canDisconnect || model.logText.isEmpty)
                // The button is disabled while connected, so explain why.
                .help(model.status.canDisconnect ? L("The log can't be cleared while connected") : "")
            }

            ScrollViewReader { proxy in
                ScrollView {
                    if model.logText.isEmpty {
                        emptyLogPlaceholder
                    } else {
                        Text(model.logText)
                            .font(.system(size: 11.5, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(14)
                        Color.clear.frame(height: 1).id("log-bottom")
                    }
                }
                .background(Color(nsColor: .textBackgroundColor).opacity(0.6), in: squircle(Theme.Radius.control))
                .overlay {
                    squircle(Theme.Radius.control).strokeBorder(.separator.opacity(0.5), lineWidth: 1)
                }
                .onChange(of: model.logText) { _ in
                    proxy.scrollTo("log-bottom", anchor: .bottom)
                }
            }
        }
        .padding(Theme.Spacing.page)
    }

    private var emptyLogPlaceholder: some View {
        VStack(spacing: 9) {
            Image(systemName: "text.append")
                .font(.system(size: 28))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tertiary)
            Text("Connection details will appear here after you connect")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 320)
    }

    // MARK: - Form helpers

    private func footnote(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: - Text and actions

    private func toggleConnection() {
        if model.status.canDisconnect {
            model.disconnect()
        } else if model.isConfigured {
            model.connect()
        } else {
            // Required fields are still empty; instead of showing an error dialog, take the user
            // straight to the fields to fill in.
            model.section = .account
        }
    }

    private var dialActionTitle: String {
        if model.status == .disconnected, !model.isConfigured { return L("Set Up") }
        return model.status.actionTitle
    }

    private var overviewTitle: String {
        switch model.status {
        case .connected: L("Connected to the remote network")
        case .connecting: L("Connecting")
        case .authorizing: L("Waiting for your authorization")
        case .disconnecting: L("Disconnecting")
        case .failed: L("Couldn't connect")
        case .disconnected: model.isConfigured ? L("Ready to connect") : L("A few settings are missing")
        }
    }

    private var connectionDescription: String {
        switch model.status {
        case .connected:
            let count = model.configuration.routes.count
            return count == 0
                ? L("The tunnel is up, but no subnets are configured, so no traffic goes through the VPN.")
                : L("Connected via \(serverEndpoint) with access to \(count) subnets.")
        case .authorizing:
            // Being asked for the Mac login password is where people hesitate most, so explain what
            // it is used for.
            return L("macOS will ask for this Mac's login password to create the VPN network interface and routes.")
        case .connecting:
            return L("Verifying your account and establishing the tunnel.")
        case .disconnecting:
            return L("Closing the tunnel and restoring network routes.")
        case .failed:
            return model.lastFailure?.summary ?? L("The connection was interrupted.")
        case .disconnected:
            guard model.isConfigured else {
                return L("Still needed: \(model.missingEssentials.localizedList).")
            }
            return model.configuration.routes.isEmpty
                ? L("No subnets configured yet; no traffic will go through the VPN once connected.")
                : L("\(model.configuration.routes.count) subnets will be reachable once connected.")
        }
    }

    private var passwordSummary: String {
        if model.password.isEmpty { return L("Not set") }
        return model.rememberPassword ? L("Saved in Keychain") : L("This session only")
    }

    private var serverEndpoint: String {
        let server = model.configuration.server.isEmpty ? L("Not set") : model.configuration.server
        return "\(server):\(model.configuration.port)"
    }

    private func copyLog() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(model.logText, forType: .string)
    }
}

// MARK: - Components

/// App glyph: a shield symbol inside a gradient rounded square.
struct AppGlyph: View {
    var size: CGFloat

    var body: some View {
        squircle(size * 0.28)
            .fill(
                LinearGradient(
                    colors: [Color(red: 0.29, green: 0.55, blue: 1), Color(red: 0.36, green: 0.29, blue: 0.9)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .overlay {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .overlay {
                squircle(size * 0.28).strokeBorder(.white.opacity(0.22), lineWidth: 0.5)
            }
            .frame(width: size, height: size)
            .shadow(color: .blue.opacity(0.25), radius: 4, y: 2)
    }
}

/// Status dot, with a spreading ripple while busy.
struct StatusDot: View {
    let color: Color
    var animated = false
    var size: CGFloat = 7

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .overlay {
                // Driven by a timeline so the ripple starts and stops correctly as the status
                // switches between busy and idle.
                if animated {
                    TimelineView(.animation) { context in
                        let cycle = 1.4
                        let phase = context.date.timeIntervalSinceReferenceDate
                            .truncatingRemainder(dividingBy: cycle) / cycle
                        Circle()
                            .stroke(color, lineWidth: 1)
                            .scaleEffect(1 + phase * 1.5)
                            .opacity(0.75 * (1 - phase))
                    }
                }
            }
    }
}

/// Notice bar with an icon, for information that needs explaining such as security notes and input
/// errors.
struct InlineNotice: View {
    let symbol: String
    let tint: Color
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: symbol)
                .font(.system(size: 15))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.callout.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(tint.opacity(0.08), in: squircle(Theme.Radius.control))
        .overlay {
            squircle(Theme.Radius.control).strokeBorder(tint.opacity(0.18), lineWidth: 1)
        }
    }
}

/// Connected duration, refreshed every second.
private struct UptimeLabel: View {
    let since: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(spacing: 6) {
                Image(systemName: "clock")
                    .font(.system(size: 11))
                Text("Connected \(elapsed(to: context.date))")
                    .monospacedDigit()
                    .contentTransition(.numericText())
            }
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(.quaternary.opacity(0.5), in: Capsule())
        }
    }

    private func elapsed(to now: Date) -> String {
        let total = max(0, Int(now.timeIntervalSince(since)))
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let seconds = total % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }
}

private struct DetailBackground: View {
    let color: Color

    var body: some View {
        ZStack {
            Color(nsColor: .windowBackgroundColor)
            RadialGradient(
                colors: [color.opacity(0.13), .clear],
                center: .init(x: 0.85, y: -0.1),
                startRadius: 0,
                endRadius: 520
            )
        }
        .ignoresSafeArea()
        .animation(.easeInOut(duration: 0.6), value: color)
    }
}

private struct CardHeader: View {
    let title: String
    let symbol: String

    var body: some View {
        Label(title, systemImage: symbol)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 18)
            .padding(.top, 12)
            .padding(.bottom, 4)
    }
}

private struct MetricCard: View {
    let title: String
    let value: String
    let symbol: String
    let color: Color

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 32, height: 32)
                .background(color.gradient, in: squircle(Theme.Radius.chip))
                .shadow(color: color.opacity(0.28), radius: 4, y: 2)

            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
        .padding(13)
        .frame(maxWidth: .infinity)
        .cardSurface(radius: Theme.Radius.control)
    }
}

private struct SummaryRow: View {
    let symbol: String
    let title: String
    let value: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
                .frame(width: 18)
            Text(title)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .fontWeight(.medium)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .font(.callout)
        .padding(.horizontal, 18)
        .padding(.vertical, 11)
    }
}

private struct RouteChip: View {
    let route: String
    var isValid = true

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: isValid ? "network" : "exclamationmark.triangle.fill")
                .font(.system(size: 11))
                .foregroundStyle(isValid ? Color.blue : Color.orange)
            Text(route)
                .font(.system(size: 12, design: .monospaced))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background((isValid ? Color.blue : Color.orange).opacity(0.09), in: squircle(Theme.Radius.chip))
        .overlay {
            squircle(Theme.Radius.chip)
                .strokeBorder((isValid ? Color.blue : Color.orange).opacity(0.16), lineWidth: 1)
        }
        .help(isValid ? "" : L("Invalid format; use the form 10.20.0.0/16"))
    }
}
