import AppKit
import SwiftUI
import VeilDNSCore

struct MainView: View {
    @Bindable var model: AppModel
    @State private var selectedPage = Page.connection

    enum Page: String, CaseIterable, Identifiable {
        case connection = "연결", domains = "도메인 규칙", about = "안내"
        var id: String { rawValue }
        var symbol: String {
            switch self {
            case .connection: "network"
            case .domains: "list.bullet.rectangle"
            case .about: "info.circle"
            }
        }
    }

    private let accent = Color(red: 0.05, green: 0.59, blue: 0.51)

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    header
                    if let message = model.message { banner(message, isError: true) }
                    if let notice = model.notice { banner(notice, isError: false) }
                    switch selectedPage {
                    case .connection: connectionPage
                    case .domains: domainsPage
                    case .about: aboutPage
                    }
                }
                .padding(30)
                .frame(maxWidth: 860, alignment: .leading)
                .frame(maxWidth: .infinity)
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(minWidth: 800, minHeight: 650)
        .tint(accent)
        .onChange(of: model.settings) { _, _ in model.saveSettings() }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 28) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(accent)
                VStack(alignment: .leading, spacing: 3) {
                    Text("VeilDNS").font(.system(size: 21, weight: .bold, design: .rounded))
                    Text("조용하게, 더 안전하게.").font(.caption2).foregroundStyle(.secondary)
                }
            }
            .padding(.top, 18)

            VStack(spacing: 5) {
                ForEach(Page.allCases) { page in
                    Button { selectedPage = page } label: {
                        Label(page.rawValue, systemImage: page.symbol)
                            .font(.system(size: 13, weight: selectedPage == page ? .semibold : .regular))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12).padding(.vertical, 11)
                            .background(selectedPage == page ? accent.opacity(0.13) : .clear, in: RoundedRectangle(cornerRadius: 9))
                            .foregroundStyle(selectedPage == page ? accent : Color.primary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(selectedPage == page ? .isSelected : [])
                }
            }
            Spacer()
            VStack(alignment: .leading, spacing: 9) {
                Label("macOS 네이티브", systemImage: "apple.logo")
                Label("오픈소스 · MIT", systemImage: "curlybraces")
            }
            .font(.caption).foregroundStyle(.secondary)
            Picker("화면 테마", selection: $model.settings.appearance) {
                Text("시스템 설정").tag("system")
                Text("라이트").tag("light")
                Text("다크").tag("dark")
            }
            .labelsHidden().accessibilityLabel("화면 테마")
        }
        .padding(20)
        .frame(width: 182)
        .background(.ultraThinMaterial)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(selectedPage == .connection ? "더 사적인 웹 연결" : selectedPage.rawValue)
                .font(.system(size: 27, weight: .bold))
            Text(selectedPage == .connection ? "암호화 DNS와 선택적 TLS 분할을 한곳에서." : selectedPage == .domains ? "필요한 연결에만 규칙을 적용하세요." : "VeilDNS가 하는 일과 적용 범위를 확인하세요.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    private var connectionPage: some View {
        VStack(alignment: .leading, spacing: 20) {
            card {
                HStack(alignment: .top, spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 17).fill(statusColor.opacity(0.12)).frame(width: 60, height: 60)
                        if model.isBusy { ProgressView().controlSize(.large) }
                        else { Image(systemName: model.isActive ? "checkmark.shield.fill" : model.state == .recovery ? "exclamationmark.shield" : "shield").font(.system(size: 29)).foregroundStyle(statusColor) }
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 7) {
                            Circle().fill(statusColor).frame(width: 7, height: 7)
                            Text(model.statusTitle).font(.headline)
                        }
                        Text(model.statusDetail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Divider().padding(.vertical, 8)
                HStack {
                    Label(model.isActive ? "127.0.0.1:8080" : "시작할 때 macOS 관리자 승인", systemImage: model.isActive ? "point.3.connected.trianglepath.dotted" : "lock.shield")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if model.state == .recovery {
                        Button("네트워크 설정 복구") { Task { await model.recover() } }
                            .buttonStyle(.borderedProminent).controlSize(.large)
                    } else {
                        Button(model.isActive ? "연결 중지" : model.isBusy ? "처리 중…" : "연결 시작") {
                            Task { if model.isActive { await model.stop() } else { await model.start() } }
                        }
                        .buttonStyle(.borderedProminent).controlSize(.large)
                        .disabled(model.isBusy || model.services.isEmpty)
                        .keyboardShortcut(.return, modifiers: .command)
                    }
                }
            }

            card {
                Label("연결 설정", systemImage: "slider.horizontal.3").font(.headline)
                VStack(alignment: .leading, spacing: 17) {
                    HStack {
                        Text("네트워크 서비스").frame(width: 120, alignment: .leading)
                        Picker("네트워크 서비스", selection: $model.settings.serviceID) {
                            if model.services.isEmpty { Text("사용 가능한 서비스 없음").tag("") }
                            ForEach(model.services) { Text($0.name).tag($0.id) }
                        }.labelsHidden()
                        Button { model.refreshServices() } label: { Image(systemName: "arrow.clockwise") }
                            .help("네트워크 서비스 새로고침").accessibilityLabel("네트워크 서비스 새로고침")
                    }
                    HStack {
                        Text("암호화 DNS").frame(width: 120, alignment: .leading)
                        Picker("암호화 DNS", selection: $model.settings.resolver) {
                            ForEach(Resolver.allCases) { Text($0.title).tag($0) }
                        }.labelsHidden()
                    }
                    HStack {
                        Text("TLS 분할").frame(width: 120, alignment: .leading)
                        Picker("TLS 분할", selection: $model.settings.fragmentation) {
                            ForEach(Fragmentation.allCases) { Text($0.title).tag($0) }
                        }.labelsHidden()
                    }
                }
                .padding(.top, 7).disabled(!model.canEdit)
                if !model.canEdit { Text("설정을 바꾸려면 먼저 연결을 중지하세요.").font(.caption).foregroundStyle(.secondary) }
                if model.settings.fragmentation == .selected && model.settings.domainsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text("선택한 도메인이 없습니다. 현재는 암호화 DNS만 사용합니다. ‘도메인 규칙’에서 분할 대상을 추가하세요.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "info.circle").foregroundStyle(accent)
                Text("시스템 프록시를 따르는 앱의 HTTP/HTTPS TCP 연결에 적용됩니다. VPN이 아니며 모든 앱·UDP·QUIC 트래픽을 보호하지 않습니다.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 3)
        }
    }

    private var domainsPage: some View {
        VStack(alignment: .leading, spacing: 20) {
            card {
                Text("TLS 분할 대상").font(.headline)
                Text("‘선택한 도메인만’ 모드에서 사용합니다. 한 줄에 하나씩 입력하세요.").font(.callout).foregroundStyle(.secondary)
                domainEditor(text: $model.settings.domainsText, label: "TLS 분할 대상 도메인")
                Text("example.com은 해당 도메인, *.example.com은 하위 도메인에 적용됩니다.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            card {
                Text("TLS 분할 제외").font(.headline)
                Text("대상 규칙보다 우선합니다. 분할로 문제가 생기는 도메인을 추가하세요. DNS 암호화와 프록시 경로는 유지됩니다.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                domainEditor(text: $model.settings.exclusionsText, label: "TLS 분할 제외 도메인")
            }
            Text("URL, IP 주소, 포트는 입력하지 마세요. 국제 도메인은 Punycode 형식을 사용합니다. 변경 사항은 다음 시작부터 적용됩니다.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var aboutPage: some View {
        VStack(alignment: .leading, spacing: 20) {
            card {
                Label("연결 내용은 그대로", systemImage: "lock.doc").font(.headline)
                Text("VeilDNS는 TLS를 복호화하거나 인증서를 설치하지 않습니다. DNS-over-HTTPS로 프록시 대상의 이름을 조회하고, 선택한 연결의 초기 TLS 데이터를 나누어 전송합니다.")
                    .font(.callout).foregroundStyle(.secondary)
                Text("분할은 네트워크 환경에 따라 효과가 다릅니다. 접속 성공이나 익명성을 보장하지 않으며 DNS 제공자는 조회 내용을 볼 수 있습니다.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            card {
                Label("네트워크 설정을 돌려놓는 방식", systemImage: "arrow.uturn.backward.circle").font(.headline)
                Text("시작 전에 기존 HTTP/HTTPS 프록시와 예외 설정을 복구 기록에 저장합니다. 다른 프록시가 켜져 있으면 시작하지 않습니다. 종료 시 VeilDNS가 설정한 값만 확인하여 복구하고, 다른 앱이 바꾼 설정은 유지합니다.")
                    .font(.callout).foregroundStyle(.secondary)
                Text("관리자 도우미는 연결 중에만 실행됩니다. 앱 또는 엔진이 종료되면 복구를 시도합니다. 강제 전원 종료나 도우미 오류 뒤에는 다음 실행에서 복구 버튼을 사용하세요.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            card {
                Label("시스템 암호화 DNS · 선택 사항", systemImage: "doc.badge.gearshape").font(.headline)
                Text("앱 밖에서도 macOS의 암호화 DNS를 쓰려면 동봉한 Cloudflare 또는 Google 프로파일을 직접 설치할 수 있습니다. 프로파일은 앱을 중지해도 유지되며 시스템 설정에서 별도로 제거해야 합니다.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 18) {
                    Button("DNS 프로파일 보기") {
                        guard let folder = Bundle.main.resourceURL?.appendingPathComponent("Profiles"),
                              FileManager.default.fileExists(atPath: folder.path) else {
                            model.message = "동봉된 DNS 프로파일을 찾을 수 없습니다. 소스 코드의 profiles 폴더를 확인해 주세요."
                            return
                        }
                        NSWorkspace.shared.open(folder)
                    }
                    Link("설치·제거 안내", destination: URL(string: "https://github.com/seungminkangg/veildns/tree/main/profiles")!)
                }.font(.callout)
            }
            card {
                Label("독립적인 오픈소스 프로젝트", systemImage: "curlybraces").font(.headline)
                Text("SecretDNS의 아이디어에서 출발한 독립 구현입니다. 길호넷의 공식 macOS 버전이 아니며 원본 코드·브랜드를 재배포하지 않습니다.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 18) {
                    Link("소스 코드", destination: URL(string: "https://github.com/seungminkangg/veildns")!)
                    Link("문제 신고", destination: URL(string: "https://github.com/seungminkangg/veildns/issues")!)
                    Link("SecretDNS 원본 안내", destination: URL(string: "https://kilho.net/archives/notice/6269")!)
                }.font(.callout)
            }
        }
    }

    private var statusColor: Color { model.isActive ? accent : model.state == .recovery ? .orange : .secondary }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 13, content: content)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(22)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Color.primary.opacity(0.065), lineWidth: 1))
    }

    private func domainEditor(text: Binding<String>, label: String) -> some View {
        TextEditor(text: text)
            .font(.system(.body, design: .monospaced))
            .scrollContentBackground(.hidden)
            .padding(9).frame(minHeight: 120)
            .background(Color.primary.opacity(0.035), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.1)))
            .disabled(!model.canEdit).accessibilityLabel(label)
    }

    private func banner(_ text: String, isError: Bool) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: isError ? "exclamationmark.triangle.fill" : "info.circle.fill")
                .foregroundStyle(isError ? .orange : accent)
            Text(text).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(15)
        .background((isError ? Color.orange : accent).opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
    }
}
