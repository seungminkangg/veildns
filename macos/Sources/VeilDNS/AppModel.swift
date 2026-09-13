import AppKit
import Foundation
import Observation
import VeilDNSCore

@MainActor
@Observable
final class AppModel {
    enum State: Equatable {
        case idle, starting, active, stopping, recovery
    }

    var settings = AppSettings()
    var services: [NetworkService] = []
    var state: State = .idle
    var message: String?
    var notice: String?
    private let engine = EngineProcess()
    private var helperTask: Task<HelperResult, Error>?
    private var helperResult: HelperResult?
    private var helperFailure: String?
    private var journal: ProxyJournal?
    private var initialized = false

    var isBusy: Bool { state == .starting || state == .stopping }
    var isActive: Bool { state == .active }
    var canEdit: Bool { state == .idle }
    var selectedService: NetworkService? { services.first { $0.id == settings.serviceID } }
    var statusTitle: String {
        switch state {
        case .idle: "연결 준비"
        case .starting: "안전하게 연결하는 중"
        case .active: "보호 연결 사용 중"
        case .stopping: "네트워크 설정 복구 중"
        case .recovery: "네트워크 설정 확인 필요"
        }
    }
    var statusDetail: String {
        switch state {
        case .idle: "시작하면 선택한 네트워크의 웹 연결에 적용합니다."
        case .starting: "엔진 상태와 실제 프록시 설정을 확인하고 있습니다."
        case .active: "\(journal?.serviceName ?? "선택한 네트워크") · HTTP / HTTPS 프록시가 적용되었습니다."
        case .stopping: "VeilDNS가 변경한 설정을 이전 상태로 돌려놓습니다."
        case .recovery: "이전 실행의 복구 기록이 있습니다. 복구 후 다시 시작하세요."
        }
    }

    func initialize() {
        guard !initialized else { return }
        initialized = true
        do {
            try SecureFiles.prepareDirectory()
            let settingsURL = SecureFiles.directory.appendingPathComponent("settings.json")
            if FileManager.default.fileExists(atPath: settingsURL.path) {
                settings = try JSONDecoder().decode(AppSettings.self, from: Data(contentsOf: settingsURL))
            }
            refreshServices()
            if FileManager.default.fileExists(atPath: SecureFiles.journalURL.path) { state = .recovery }
        } catch { message = error.localizedDescription }
        engine.onExit = { [weak self] in
            guard let self, self.state == .active else { return }
            self.message = "네트워크 엔진이 종료되었습니다. 이전 프록시 설정을 복구합니다."
            Task { await self.stop() }
        }
    }

    func refreshServices() {
        do {
            services = try SystemProxy.services()
            if !services.contains(where: { $0.id == settings.serviceID }) {
                settings.serviceID = services.first?.id ?? ""
            }
        } catch { message = error.localizedDescription }
    }

    func saveSettings() {
        do {
            try SecureFiles.write(JSONEncoder().encode(settings), to: SecureFiles.directory.appendingPathComponent("settings.json"))
        } catch { message = error.localizedDescription }
    }

    func start() async {
        guard state == .idle else { return }
        message = nil; notice = nil; state = .starting
        helperResult = nil; helperFailure = nil
        do {
            guard !FileManager.default.fileExists(atPath: SecureFiles.journalURL.path) else {
                throw VeilError.message("이전 실행의 네트워크 설정을 먼저 복구해 주세요.")
            }
            guard let service = selectedService else { throw VeilError.message("적용할 네트워크 서비스를 선택해 주세요.") }
            let configuration = try settings.engineConfiguration()
            let original = try SystemProxy.read(serviceID: service.id)
            try ProxyPlan.validateOriginal(original)
            saveSettings()
            let configURL = SecureFiles.directory.appendingPathComponent("engine.json")
            try SecureFiles.write(JSONEncoder().encode(configuration), to: configURL)
            try await engine.start(configurationURL: configURL)
            let snapshot = try ProxyJournal(serviceID: service.id, serviceName: service.name, original: original,
                ownerUID: getuid(), appPID: getpid(), enginePID: engine.pid)
            journal = snapshot
            // Persist the full original dictionary before any privileged mutation.
            try SecureFiles.write(JSONEncoder().encode(snapshot), to: SecureFiles.journalURL)
            helperTask = Task { [weak self] in
                do {
                    let result = try await HelperProcess.run(operation: "watch")
                    self?.helperResult = result
                    if self?.state == .active {
                        self?.message = "네트워크 도우미가 종료되어 연결을 중단합니다."
                        Task { await self?.stop() }
                    }
                    return result
                } catch {
                    self?.helperFailure = error.localizedDescription
                    throw error
                }
            }
            // Allow time for the macOS authorization dialog. Never display green based only on a process launch.
            for _ in 0..<1200 {
                if let failure = helperFailure { throw VeilError.message(failure) }
                if let result = helperResult {
                    throw VeilError.message(result.error.isEmpty ? "네트워크 설정 적용이 취소되었습니다." : result.error)
                }
                guard engine.isRunning else { throw VeilError.message("엔진이 종료되어 연결을 중단했습니다.") }
                let current = try SystemProxy.read(serviceID: snapshot.serviceID)
                if ProxyPlan.isOwned(current, original: original) {
                    state = .active
                    return
                }
                try await Task.sleep(for: .milliseconds(100))
            }
            throw VeilError.message("권한 승인 시간이 초과되었습니다. 승인 대화상자를 취소한 뒤 다시 시도해 주세요.")
        } catch {
            message = error.localizedDescription
            state = .stopping
            await engine.stop()
            await finishRestoration()
        }
    }

    func stop() async {
        guard state == .active else { return }
        state = .stopping
        await engine.stop()
        await finishRestoration()
    }

    private func finishRestoration() async {
        // The privileged watcher restores on engine exit without asking for credentials again.
        for _ in 0..<150 {
            if helperTask == nil || helperResult != nil || helperFailure != nil { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
        do {
            if let snapshot = journal {
                let current = try SystemProxy.read(serviceID: snapshot.serviceID)
                let original = try snapshot.original()
                let assessment = ProxyPlan.restoration(current: current, original: original)
                let stillOwned = ProxyPlan.groups.contains { group in
                    let installed = ProxyPlan.installed(on: original)
                    return group.allSatisfy { ProxyPlan.equal(current[$0], installed[$0]) }
                }
                guard !stillOwned, helperResult != nil || helperFailure != nil || helperTask == nil else {
                    throw VeilError.message("복구 완료를 확인하지 못했습니다. 권한 대화상자를 취소하고 복구 버튼을 눌러 주세요.")
                }
                if !assessment.conflicts.isEmpty {
                    notice = "다른 곳에서 변경한 \(assessment.conflicts.joined(separator: ", ")) 설정을 그대로 유지했습니다. 시스템 설정에서 연결 상태를 확인해 주세요."
                }
                try removeJournal()
            }
            state = FileManager.default.fileExists(atPath: SecureFiles.journalURL.path) ? .recovery : .idle
        } catch {
            state = .recovery
            message = error.localizedDescription
        }
    }

    func recover() async {
        guard state == .recovery else { return }
        // A pending authorization dialog could still launch the old watcher. Its process is already dead,
        // but retain the record until that invocation completes so it cannot race a future session.
        guard helperTask == nil || helperResult != nil || helperFailure != nil else {
            message = "열려 있는 macOS 권한 대화상자를 취소한 다음 복구를 다시 눌러 주세요."
            return
        }
        state = .stopping; message = nil
        do {
            let snapshot = try SecureFiles.readJournal(path: SecureFiles.journalURL.path, ownerUID: getuid())
            let result = try await HelperProcess.run(operation: "restore")
            guard result.restored else { throw VeilError.message(result.error.isEmpty ? "복구를 완료하지 못했습니다." : result.error) }
            let current = try SystemProxy.read(serviceID: snapshot.serviceID)
            let original = try snapshot.original()
            let stillOwned = ProxyPlan.groups.contains { group in
                let installed = ProxyPlan.installed(on: original)
                return group.allSatisfy { ProxyPlan.equal(current[$0], installed[$0]) }
            }
            guard !stillOwned else { throw VeilError.message("프록시가 여전히 적용되어 있습니다. 복구 기록을 유지합니다.") }
            if !result.preservedChanges.isEmpty { notice = "다른 앱에서 변경한 \(result.preservedChanges.joined(separator: ", ")) 설정을 유지했습니다." }
            try removeJournal()
            state = .idle
        } catch { message = error.localizedDescription; state = .recovery }
    }

    private func removeJournal() throws {
        if FileManager.default.fileExists(atPath: SecureFiles.journalURL.path) {
            try FileManager.default.removeItem(at: SecureFiles.journalURL)
        }
        journal = nil; helperTask = nil; helperResult = nil; helperFailure = nil
    }

    func prepareToQuit() async -> Bool {
        if state == .active { await stop() }
        if state == .starting || state == .stopping { return false }
        // Recovery records deliberately survive termination; never silently discard them.
        return state != .recovery
    }
}
