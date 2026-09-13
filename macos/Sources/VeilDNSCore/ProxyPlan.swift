import Foundation

public struct ProxyJournal: Codable, Sendable {
    public var version = 1
    public let serviceID: String
    public let serviceName: String
    public let originalPropertyList: Data
    public let ownerUID: UInt32
    public let appPID: Int32
    public let enginePID: Int32
    public let createdAt: Date
    public let port: Int

    public init(serviceID: String, serviceName: String, original: [String: Any], ownerUID: UInt32,
                appPID: Int32, enginePID: Int32, port: Int = 8080) throws {
        self.serviceID = serviceID
        self.serviceName = serviceName
        originalPropertyList = try PropertyListSerialization.data(fromPropertyList: original, format: .binary, options: 0)
        self.ownerUID = ownerUID
        self.appPID = appPID
        self.enginePID = enginePID
        self.port = port
        createdAt = Date()
    }

    public func original() throws -> [String: Any] {
        guard version == 1, port == 8080, !serviceID.isEmpty, serviceID.count <= 128,
              ownerUID != 0, appPID > 1, enginePID > 1,
              let original = try PropertyListSerialization.propertyList(from: originalPropertyList, options: [], format: nil) as? [String: Any] else {
            throw VeilError.message("복구 기록의 형식이 올바르지 않습니다. 네트워크 설정을 직접 확인해 주세요.")
        }
        return original
    }
}

public enum ProxyPlan {
    public static let groups = [["HTTPEnable", "HTTPProxy", "HTTPPort"], ["HTTPSEnable", "HTTPSProxy", "HTTPSPort"]]
    private static let conflicts = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]

    public static func validateOriginal(_ original: [String: Any]) throws {
        guard !conflicts.contains(where: { (original[$0] as? NSNumber)?.boolValue == true }) else {
            throw VeilError.message("선택한 네트워크에 다른 프록시 또는 자동 프록시가 켜져 있습니다. 기존 설정을 먼저 확인해 주세요.")
        }
    }

    public static func installed(on original: [String: Any], port: Int = 8080) -> [String: Any] {
        var result = original
        for group in groups {
            result[group[0]] = 1
            result[group[1]] = "127.0.0.1"
            result[group[2]] = port
        }
        return result
    }

    /// Restores a protocol only if its entire owned tuple still matches. Other keys are never replaced.
    public static func restoration(current: [String: Any], original: [String: Any], port: Int = 8080) -> (settings: [String: Any], conflicts: [String]) {
        let owned = installed(on: original, port: port)
        var restored = current
        var changed: [String] = []
        for group in groups {
            if group.allSatisfy({ equal(current[$0], owned[$0]) }) {
                for key in group { restored[key] = original[key] }
            } else if !group.allSatisfy({ equal(current[$0], original[$0]) }) {
                changed.append(group[0] == "HTTPEnable" ? "HTTP" : "HTTPS")
            }
        }
        return (restored, changed)
    }

    public static func isOwned(_ settings: [String: Any], original: [String: Any], port: Int = 8080) -> Bool {
        let owned = installed(on: original, port: port)
        return groups.allSatisfy { group in group.allSatisfy { equal(settings[$0], owned[$0]) } }
    }

    public static func equal(_ lhs: Any?, _ rhs: Any?) -> Bool {
        switch (lhs, rhs) {
        case (nil, nil): true
        case let (left as NSObject, right as NSObject): left.isEqual(right)
        default: false
        }
    }
}
