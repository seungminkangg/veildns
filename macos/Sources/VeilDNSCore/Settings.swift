import Foundation

public enum Resolver: String, Codable, CaseIterable, Sendable, Identifiable {
    case cloudflare, google
    public var id: String { rawValue }
    public var title: String { self == .cloudflare ? "Cloudflare · 1.1.1.1" : "Google · 8.8.8.8" }
}

public enum Fragmentation: String, Codable, CaseIterable, Sendable, Identifiable {
    case selected, all, off
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .selected: "선택한 도메인만"
        case .all: "모든 HTTPS 연결"
        case .off: "사용 안 함"
        }
    }
}

public struct AppSettings: Codable, Equatable, Sendable {
    public var resolver: Resolver = .google
    public var fragmentation: Fragmentation = .all
    public var domainsText = ""
    public var exclusionsText = ""
    public var serviceID = ""
    public var appearance = "system"
    public init() {}

    public func engineConfiguration() throws -> EngineConfiguration {
        .init(resolver: resolver, fragmentation: fragmentation,
              domains: try DomainRules.parse(domainsText), exclusions: try DomainRules.parse(exclusionsText))
    }
}

public struct EngineConfiguration: Codable, Equatable, Sendable {
    public let listenPort = 8080
    public let resolver: Resolver
    public let fragmentation: Fragmentation
    public let domains: [String]
    public let exclusions: [String]
    public let fragmentDelayMS = 5
    public let allowPrivate = false

    enum CodingKeys: String, CodingKey {
        case listenPort = "listen_port", resolver, fragmentation, domains, exclusions
        case fragmentDelayMS = "fragment_delay_ms", allowPrivate = "allow_private"
    }

    public init(resolver: Resolver, fragmentation: Fragmentation, domains: [String], exclusions: [String]) {
        self.resolver = resolver
        self.fragmentation = fragmentation
        self.domains = domains
        self.exclusions = exclusions
    }
}

public enum DomainRules {
    public static func parse(_ text: String) throws -> [String] {
        var result: [String] = []
        for line in text.components(separatedBy: .newlines) {
            let domain = line.trimmingCharacters(in: .whitespaces).lowercased()
            if domain.isEmpty { continue }
            let host = domain.hasPrefix("*.") ? String(domain.dropFirst(2)) : domain
            let labels = host.split(separator: ".", omittingEmptySubsequences: false)
            guard domain.utf8.count <= 253, labels.count >= 2,
                  labels.allSatisfy({ label in
                      !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-"
                          && label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
                  }), labels.last?.contains(where: { $0.isLetter }) == true else {
                throw VeilError.message("올바른 도메인을 한 줄에 하나씩 입력하세요: \(domain.prefix(80))\n예: example.com 또는 *.example.com (국제 도메인은 Punycode)")
            }
            if !result.contains(domain) { result.append(domain) }
            guard result.count <= 1024 else { throw VeilError.message("도메인은 최대 1,024개까지 지정할 수 있습니다.") }
        }
        return result
    }
}

public enum VeilError: Error, LocalizedError, Sendable {
    case message(String)
    public var errorDescription: String? {
        if case let .message(message) = self { message } else { nil }
    }
}

public enum CommandEscaping {
    public static func shell(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    public static func appleScript(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\n", with: "\\n") + "\""
    }

    public static func privilegedInvocation(executable: String, arguments: [String]) -> String {
        let command = ([executable] + arguments).map(shell).joined(separator: " ")
        return "with timeout of 86400 seconds\n do shell script \(appleScript(command)) with administrator privileges\nend timeout"
    }
}
