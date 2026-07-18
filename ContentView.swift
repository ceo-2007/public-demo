import Network
import SwiftUI
import UIKit

// MARK: - Models
struct SecurityCheckItem: Identifiable {
    let id = UUID()
    let title: String
    let description: String
    let severity: Severity
    let actionHint: String

    enum Severity: String {
        case low = "低"
        case medium = "中"
        case high = "高"
    }
}

struct IPInfo: Codable {
    let ip: String
}

// MARK: - ViewModel
@MainActor
final class SecurityScanViewModel: ObservableObject {
    @Published var publicIP: String = "尚未取得"
    @Published var isFetchingIP: Bool = false
    @Published var vpnLikelyOn: Bool = false
    @Published var vpnStatusText: String = "未知"

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "net.monitor.queue")

    func startNetworkMonitor() {
        monitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                // 這是「基礎判斷」：使用 iOS 網路介面類型推測
                // 不能 100% 準確，但很實用
                let usesOther = path.usesInterfaceType(.other)
                self?.vpnLikelyOn = usesOther
                self?.vpnStatusText = usesOther ? "疑似啟用中" : "未偵測到"
            }
        }
        monitor.start(queue: queue)
    }

    func fetchPublicIP() async {
        isFetchingIP = true
        defer { isFetchingIP = false }

        guard let url = URL(string: "https://api.ipify.org?format=json") else {
            publicIP = "URL 錯誤"
            return
        }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let info = try JSONDecoder().decode(IPInfo.self, from: data)
            publicIP = info.ip
        } catch {
            publicIP = "取得失敗"
        }
    }
}

// MARK: - Views
struct ContentView: View {
    @StateObject private var vm = SecurityScanViewModel()
    @State private var completedChecks: Set<UUID> = []

    private var checks: [SecurityCheckItem] = [
        .init(
            title: "檢查是否有「描述檔 / MDM 管理」",
            description: "若有企業/學校管理設定檔，可能影響裝置權限與流量路由。",
            severity: .high,
            actionHint: "設定 → 一般 → VPN 與裝置管理"
        ),
        .init(
            title: "檢查定位權限（永遠定位）",
            description: "不必要的 App 若拿到永遠定位，等於行蹤被長期追蹤。",
            severity: .high,
            actionHint: "設定 → 隱私權與安全性 → 定位服務"
        ),
        .init(
            title: "檢查麥克風/相機權限",
            description: "陌生 App 有麥克風/相機權限就很危險。",
            severity: .high,
            actionHint: "設定 → 隱私權與安全性 → 麥克風 / 相機"
        ),
        .init(
            title: "檢查 Apple ID 登入裝置",
            description: "陌生裝置登入代表帳號可能被接管。",
            severity: .high,
            actionHint: "設定 → 你的名字 → 裝置列表"
        ),
        .init(
            title: "檢查 VPN / DNS 設定",
            description: "VPN 或自訂 DNS 可能讓流量被導走或被記錄。",
            severity: .medium,
            actionHint: "設定 → 一般 → VPN 與裝置管理 / Wi-Fi"
        ),
        .init(
            title: "檢查行動數據與電池異常",
            description: "背景耗電/流量異常的 App，常常就是問題源頭。",
            severity: .medium,
            actionHint: "設定 → 電池 / 行動服務"
        )
    ]

    var body: some View {
        NavigationStack {
            List {
                Section("即時網路狀態") {
                    HStack {
                        Text("Public IP")
                        Spacer()
                        Text(vm.publicIP)
                            .foregroundStyle(.secondary)
                            .monospaced()
                    }

                    HStack {
                        Text("VPN 狀態")
                        Spacer()
                        Text(vm.vpnStatusText)
                            .foregroundStyle(vm.vpnLikelyOn ? .orange : .secondary)
                    }

                    Button {
                        Task { await vm.fetchPublicIP() }
                    } label: {
                        HStack {
                            Image(systemName: "arrow.clockwise")
                            Text(vm.isFetchingIP ? "取得中..." : "重新取得 IP")
                        }
                    }
                    .disabled(vm.isFetchingIP)
                }

                Section("安全檢查清單") {
                    ForEach(checks) { item in
                        NavigationLink {
                            CheckDetailView(
                                item: item,
                                isComplete: binding(for: item),
                                openSettings: openAppSettings
                            )
                        } label: {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(item.title)
                                        .font(.headline)
                                    Spacer()
                                    SeverityBadge(severity: item.severity)
                                }
                                if completedChecks.contains(item.id) {
                                    Label("已檢查", systemImage: "checkmark.circle.fill")
                                        .font(.caption)
                                        .foregroundStyle(.green)
                                }
                                Text(item.description)
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }

                Section("快速操作") {
                    Button(action: openAppSettings) {
                        HStack {
                            Image(systemName: "gear")
                            Text("開啟 App 設定頁")
                        }
                    }

                    Button(action: copyPublicIP) {
                        HStack {
                            Image(systemName: "doc.on.doc")
                            Text("複製 Public IP")
                        }
                    }
                    .disabled(vm.publicIP == "尚未取得" || vm.publicIP == "取得失敗")
                }
            }
            .navigationTitle("安全健檢")
            .onAppear {
                vm.startNetworkMonitor()
                Task { await vm.fetchPublicIP() }
            }
        }
    }

    private func openAppSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    private func copyPublicIP() {
        UIPasteboard.general.string = vm.publicIP
    }

    private func binding(for item: SecurityCheckItem) -> Binding<Bool> {
        Binding(
            get: { completedChecks.contains(item.id) },
            set: { isComplete in
                if isComplete {
                    completedChecks.insert(item.id)
                } else {
                    completedChecks.remove(item.id)
                }
            }
        )
    }
}

struct CheckDetailView: View {
    let item: SecurityCheckItem
    @Binding var isComplete: Bool
    let openSettings: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(item.title)
                .font(.title2.bold())

            HStack(spacing: 10) {
                Text("風險等級")
                    .foregroundStyle(.secondary)
                SeverityBadge(severity: item.severity)
            }

            Text(item.description)
                .font(.body)

            VStack(alignment: .leading, spacing: 8) {
                Text("你要去哪裡檢查")
                    .font(.headline)
                Text(item.actionHint)
                    .font(.body)
                    .foregroundStyle(.secondary)
            }

            Toggle(isOn: $isComplete) {
                Text("標記為已檢查")
                    .font(.headline)
            }
            .tint(.green)

            Button(action: openSettings) {
                HStack {
                    Image(systemName: "gearshape")
                    Text("前往設定檢查")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

            Spacer()
        }
        .padding()
        .navigationTitle("檢查項目")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct SeverityBadge: View {
    let severity: SecurityCheckItem.Severity

    var body: some View {
        Text(severity.rawValue)
            .font(.caption.bold())
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(backgroundColor.opacity(0.15))
            .foregroundStyle(backgroundColor)
            .clipShape(Capsule())
    }

    private var backgroundColor: Color {
        switch severity {
        case .low: return .green
        case .medium: return .orange
        case .high: return .red
        }
    }
}
