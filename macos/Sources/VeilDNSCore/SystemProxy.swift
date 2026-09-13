#if os(macOS)
import Foundation
import SystemConfiguration

public struct NetworkService: Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
}

public enum SystemProxy {
    private static func preferences() throws -> SCPreferences {
        guard let prefs = SCPreferencesCreate(nil, "VeilDNS" as CFString, nil) else {
            throw VeilError.message("네트워크 설정을 읽을 수 없습니다.")
        }
        return prefs
    }

    public static func services() throws -> [NetworkService] {
        let prefs = try preferences()
        guard let set = SCNetworkSetCopyCurrent(prefs),
              let services = SCNetworkSetCopyServices(set) as? [SCNetworkService] else { return [] }
        return services.filter(SCNetworkServiceGetEnabled).compactMap { service in
            guard let name = SCNetworkServiceGetName(service), let id = SCNetworkServiceGetServiceID(service),
                  SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) != nil else { return nil }
            return NetworkService(id: id as String, name: name as String)
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private static func proxyProtocol(_ prefs: SCPreferences, serviceID: String) throws -> SCNetworkProtocol {
        guard let service = SCNetworkServiceCopy(prefs, serviceID as CFString),
              let protocolValue = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
            throw VeilError.message("네트워크 서비스를 찾을 수 없습니다. 복구 기록은 보관됩니다.")
        }
        return protocolValue
    }

    public static func read(serviceID: String) throws -> [String: Any] {
        let proxy = try proxyProtocol(preferences(), serviceID: serviceID)
        return SCNetworkProtocolGetConfiguration(proxy) as? [String: Any] ?? [:]
    }

    /// Configd's published setup is distinct from merely committed preferences.
    public static func applied(serviceID: String) throws -> [String: Any] {
        guard let store = SCDynamicStoreCreate(nil, "VeilDNS status" as CFString, nil, nil) else {
            throw VeilError.message("적용된 네트워크 상태를 확인할 수 없습니다.")
        }
        let key = SCDynamicStoreKeyCreateNetworkServiceEntity(nil, kSCDynamicStoreDomainSetup,
            serviceID as CFString, kSCEntNetProxies)
        return SCDynamicStoreCopyValue(store, key) as? [String: Any] ?? [:]
    }

    public static func apply(_ journal: ProxyJournal) throws {
        let original = try journal.original()
        try ProxyPlan.validateOriginal(original)
        try mutate(serviceID: journal.serviceID) { current in
            guard NSDictionary(dictionary: current).isEqual(to: original) else {
                throw VeilError.message("시작 중 네트워크 설정이 변경되어 적용을 중단했습니다.")
            }
            return ProxyPlan.installed(on: original, port: journal.port)
        }
    }

    @discardableResult
    public static func restore(_ journal: ProxyJournal) throws -> [String] {
        let original = try journal.original()
        try ProxyPlan.validateOriginal(original)
        var conflicts: [String] = []
        try mutate(serviceID: journal.serviceID) { current in
            let result = ProxyPlan.restoration(current: current, original: original, port: journal.port)
            conflicts = result.conflicts
            return result.settings
        }
        return conflicts
    }

    private static func mutate(serviceID: String, transform: ([String: Any]) throws -> [String: Any]) throws {
        let prefs = try preferences()
        guard SCPreferencesLock(prefs, false) else {
            throw VeilError.message("다른 앱이 네트워크 설정을 수정 중입니다. 잠시 후 다시 시도해 주세요.")
        }
        defer { SCPreferencesUnlock(prefs) }
        let proxy = try proxyProtocol(prefs, serviceID: serviceID)
        let before = SCNetworkProtocolGetConfiguration(proxy) as? [String: Any] ?? [:]
        let after = try transform(before)
        if NSDictionary(dictionary: before).isEqual(to: after) { return }
        guard SCNetworkProtocolSetConfiguration(proxy, after as CFDictionary), SCPreferencesCommitChanges(prefs) else {
            throw VeilError.message("네트워크 설정을 저장하지 못했습니다. 복구 기록을 유지합니다.")
        }
        guard SCPreferencesApplyChanges(prefs) else {
            // Persisted changes already exist: best-effort rollback under the same lock, never discard journal.
            let reset = SCNetworkProtocolSetConfiguration(proxy, before as CFDictionary)
            let committed = reset && SCPreferencesCommitChanges(prefs)
            let applied = committed && SCPreferencesApplyChanges(prefs)
            throw VeilError.message(applied ? "네트워크 적용에 실패하여 이전 설정으로 되돌렸습니다." : "네트워크 적용과 자동 복구에 실패했습니다. 앱의 복구 버튼을 사용해 주세요.")
        }
    }
}
#endif
