import SwiftUI
import UniformTypeIdentifiers
import SHAIPCore

/// First run: import the server config the operator handed out (the same
/// client.toml the `shaip` CLI reads), then enroll the device if the server
/// requires it. Nothing works without a real server, so nothing pretends to.
struct SetupView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(Router.self) private var router
    @State private var importing = false
    @State private var pasting = false
    @State private var error: String?

    /// The welcome mesh is art, not a status display (there is no server yet), so it is always
    /// drawn in full colour; the Connect screen's mesh is the one that follows the tunnel.
    private static let artOptions: SceneOptions = {
        var o = SceneOptions()
        o.hud = false
        return o
    }()

    var body: some View {
        ZStack(alignment: .bottom) {
            ScreenBackground()
            GeometryReader { geo in
                SceneView(.net, layout: SceneLayout(cy: 0.5, r: 0.4), options: Self.artOptions)
                    .frame(width: geo.size.width, height: 540)
                    .offset(y: 30)
                    .accessibilityHidden(true)
                LinearGradient(stops: [.init(color: Tok.bgBottom.opacity(0), location: 0), .init(color: Color(hex: 0x03040A), location: 0.8)],
                               startPoint: .top, endPoint: .bottom)
                    .frame(height: 240)
                    .offset(y: 400)
                    .allowsHitTesting(false)
                Color(hex: 0x03040A).frame(height: max(0, geo.size.height - 640)).offset(y: 640)
            }
            .ignoresSafeArea()

            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 8) {
                    GlowDot(color: Tok.signal, glow: 10)
                    Text("SHAIP/1 · POST-QUANTUM VPN").mono(10, .medium).em(0.16, of: 10).foregroundStyle(Tok.signal)
                }
                Text("Your traffic, encrypted to a server you choose.")
                    .ui(38, .semibold, relativeTo: .largeTitle).em(-0.045, of: 38)
                    .foregroundStyle(LinearGradient(stops: [.init(color: .white, location: 0.3), .init(color: Color(hex: 0xA9B4D6), location: 1)],
                                                    startPoint: .top, endPoint: .bottom))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                Text("Import the config your server's operator gave you. Traffic and DNS lookups between this iPhone and that server are encrypted. The operator can still see where your traffic goes.")
                    .ui(15).lineSpacing(4).foregroundStyle(Tok.dim(0.56))
                    .fixedSize(horizontal: false, vertical: true)
                if let error {
                    Text(error).ui(13, relativeTo: .footnote).foregroundStyle(Tok.warn).fixedSize(horizontal: false, vertical: true)
                }
                VStack(spacing: 10) {
                    Button { importing = true } label: {
                        Label("Import config file", systemImage: "doc.badge.plus")
                            .ui(17, .semibold).em(-0.01, of: 17)
                            .foregroundStyle(Color(hex: 0x05060A))
                            .frame(maxWidth: .infinity, minHeight: 56)
                            .background {
                                Capsule(style: .continuous)
                                    .fill(LinearGradient(colors: [.white, Color(hex: 0xDCE3F2)], startPoint: .top, endPoint: .bottom)
                                        .shadow(.inner(color: .black.opacity(0.15), radius: 0, x: 0, y: -1)))
                                    .shadow(color: Tok.signal.opacity(0.45), radius: 17, x: 0, y: 14)
                            }
                    }
                    .buttonStyle(PressScaleStyle())
                    Button { pasting = true } label: {
                        Label("Paste config", systemImage: "doc.on.clipboard")
                            .ui(17, .medium)
                            .foregroundStyle(Tok.ink)
                            .frame(maxWidth: .infinity, minHeight: 56)
                            .contentShape(Capsule())
                    }
                    .buttonStyle(PressScaleStyle())
                    .liquidGlass(in: Capsule(style: .continuous))
                }
                .padding(.top, 4)
                Text("PRE-RELEASE · NOT YET INDEPENDENTLY AUDITED")
                    .mono(9, .medium).em(0.16, of: 9).foregroundStyle(Tok.dim(0.38))
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 8)
        }
        .preferredColorScheme(.dark)
        .fileImporter(isPresented: $importing, allowedContentTypes: ConfigFile.types) { result in
            Task { await adopt(ConfigFile.read(result)) }
        }
        .sheet(isPresented: $pasting) {
            ImportConfigSheet { config in try await install(config) }.privacyCover()
        }
    }

    private func adopt(_ text: Result<String, Error>) async {
        do {
            try await install(try ServerConfig.parse(text.get()))
        } catch {
            self.error = String(describing: error)
        }
    }

    private func install(_ config: ServerConfig) async throws {
        try await store.install(config)
        error = nil
        if config.canEnroll && !store.enrolled {
            // The cover closes now that a server exists; offer enrollment next.
            router.pendingEnrollLink = ""
        }
    }
}

/// Reading a config from the Files app.
enum ConfigFile {
    static var types: [UTType] {
        [UTType(filenameExtension: "toml"), .plainText, .text].compactMap { $0 }
    }

    static func read(_ result: Result<URL, Error>) -> Result<String, Error> {
        result.flatMap { url in
            Result {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                return try String(contentsOf: url, encoding: .utf8)
            }
        }
    }
}

/// Paste (or pick) a config; validated before anything is saved.
struct ImportConfigSheet: View {
    let onImport: (ServerConfig) async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var picking = false
    @State private var error: String?
    @State private var working = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paste the client config from your server's operator. It needs the [server] address, server_ml_dsa_pub and server_ed_pub (from shaipd --print-public).")
                    .ui(13, relativeTo: .footnote).foregroundStyle(Tok.dim(0.6)).fixedSize(horizontal: false, vertical: true)
                TextEditor(text: $text)
                    .font(.system(size: 12, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.white.opacity(0.05)))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.white.opacity(0.12), lineWidth: 0.5))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                if let error {
                    Text(error).ui(13, relativeTo: .footnote).foregroundStyle(Tok.warn).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(16)
            .background(ScreenBackground())
            .navigationTitle("Server config")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .topBarLeading) {
                    Button { picking = true } label: { Image(systemName: "folder") }
                        .accessibilityLabel("Choose a file")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save(text) } }
                        .disabled(text.isEmpty || working)
                }
            }
            .fileImporter(isPresented: $picking, allowedContentTypes: ConfigFile.types) { result in
                if case .success(let s) = ConfigFile.read(result) { text = s }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func save(_ text: String) async {
        working = true
        defer { working = false }
        do {
            try await onImport(try ServerConfig.parse(text))
            dismiss()
        } catch {
            self.error = String(describing: error)
        }
    }
}

/// Enroll this device with a `shaip://enroll` link.
struct EnrollSheet: View {
    @Environment(TunnelStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    @State var link: String
    @State private var error: String?
    @State private var working = false
    @State private var done = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("Servers that admit enrolled devices only need this once per device. Paste the enrollment link from your account page; this iPhone proves it holds its own key and receives a certificate.")
                    .ui(13, relativeTo: .footnote).foregroundStyle(Tok.dim(0.6)).fixedSize(horizontal: false, vertical: true)
                TextField("shaip://enroll?t=…", text: $link, axis: .vertical)
                    .font(.system(size: 12, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Color.white.opacity(0.05)))
                if let error {
                    Text(error).ui(13, relativeTo: .footnote).foregroundStyle(Tok.warn).fixedSize(horizontal: false, vertical: true)
                }
                if done {
                    Label("Enrolled. You can connect now.", systemImage: "checkmark.circle.fill").ui(14, .semibold).foregroundStyle(Tok.ok)
                }
                Spacer()
            }
            .padding(16)
            .background(ScreenBackground())
            .navigationTitle("Enroll this device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(done ? "Done" : "Not now") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Enroll") { Task { await enroll() } }
                        .disabled(link.isEmpty || working || done)
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private func enroll() async {
        working = true
        defer { working = false }
        do {
            try await store.enroll(link: link.trimmingCharacters(in: .whitespacesAndNewlines))
            error = nil
            done = true
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// Subtle press feedback for full-width buttons.
struct PressScaleStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .opacity(configuration.isPressed ? 0.9 : 1)
            .animation(.smooth(duration: 0.2), value: configuration.isPressed)
    }
}
