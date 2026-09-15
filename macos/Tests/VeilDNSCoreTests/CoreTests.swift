import Foundation
import Testing
@testable import VeilDNSCore

@Suite("Domain rules and engine contract")
struct ConfigurationTests {
    @Test func domainsNormalizeAndDeduplicate() throws {
        #expect(try DomainRules.parse("  EXAMPLE.com\n*.Example.com\n\nexample.com\r\n") == ["example.com", "*.example.com"])
    }

    @Test(arguments: ["https://example.com", "example.com/path", "127.0.0.1", "example.com:443", "foo..com", "-foo.com", "foo-.com", "*example.com", "localhost", "한글.kr", "example.com;id", "example.com\u{0}"])
    func invalidRulesAreRejected(domain: String) {
        #expect(throws: VeilError.self) { try DomainRules.parse(domain) }
    }

    @Test func boundariesAreEnforced() {
        #expect(throws: VeilError.self) { try DomainRules.parse(String(repeating: "a", count: 64) + ".com") }
        #expect(throws: VeilError.self) { try DomainRules.parse((0..<1025).map { "host\($0).example.com" }.joined(separator: "\n")) }
    }

    @Test func engineContractHasExactNamesAndSafeDefaults() throws {
        let data = try JSONEncoder().encode(AppSettings().engineConfiguration())
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == ["listen_port", "resolver", "fragmentation", "domains", "exclusions", "fragment_delay_ms", "allow_private"])
        #expect(object["listen_port"] as? Int == 8080)
        #expect(object["resolver"] as? String == "google")
        #expect(object["fragmentation"] as? String == "all")
        #expect(object["allow_private"] as? Bool == false)
        #expect(object["fragment_delay_ms"] as? Int == 5)
        #expect(object["domains"] as? [String] == [])
    }

    @Test func settingsRoundTrip() throws {
        var settings = AppSettings()
        settings.resolver = .google
        settings.domainsText = "*.example.com"
        settings.exclusionsText = "login.example.com"
        settings.serviceID = "test-service"
        #expect(try JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(settings)) == settings)
    }
}

@Suite("Proxy ownership and restoration")
struct ProxyPlanTests {
    @Test(arguments: ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"])
    func refusesExistingEnabledProxy(key: String) {
        #expect(throws: VeilError.self) { try ProxyPlan.validateOriginal([key: 1]) }
    }

    @Test func restoresAbsentKeysExactly() throws {
        let original: [String: Any] = ["ExceptionsList": ["*.local", "169.254/16"], "ExcludeSimpleHostnames": 1]
        try ProxyPlan.validateOriginal(original)
        let installed = ProxyPlan.installed(on: original)
        #expect(ProxyPlan.isOwned(installed, original: original))
        let restored = ProxyPlan.restoration(current: installed, original: original)
        #expect(NSDictionary(dictionary: restored.settings).isEqual(to: original))
        #expect(restored.conflicts.isEmpty)
        #expect(restored.settings["HTTPProxy"] == nil)
        #expect(restored.settings["HTTPSPort"] == nil)
    }

    @Test func restoresDisabledProxyAddressAndPreservesUnrelatedEdits() {
        let original: [String: Any] = ["HTTPEnable": 0, "HTTPProxy": "old.example", "HTTPPort": 3128,
                                       "HTTPSEnable": 0, "HTTPSProxy": "", "HTTPSPort": 0, "ExceptionsList": ["*.local"]]
        var current = ProxyPlan.installed(on: original)
        current["ExceptionsList"] = ["*.new.example"]
        current["ProxyAutoConfigEnable"] = 1
        let restored = ProxyPlan.restoration(current: current, original: original)
        #expect(restored.settings["HTTPProxy"] as? String == "old.example")
        #expect(restored.settings["HTTPPort"] as? Int == 3128)
        #expect(restored.settings["HTTPSProxy"] as? String == "")
        #expect(restored.settings["HTTPSPort"] as? Int == 0)
        #expect(restored.settings["ExceptionsList"] as? [String] == ["*.new.example"])
        #expect(restored.settings["ProxyAutoConfigEnable"] as? Int == 1)
    }

    @Test func preservesWholeProtocolWhenItsOwnedTupleChanges() {
        let original: [String: Any] = [:]
        var current = ProxyPlan.installed(on: original)
        current["HTTPPort"] = 9999
        let result = ProxyPlan.restoration(current: current, original: original)
        #expect(result.conflicts == ["HTTP"])
        #expect(result.settings["HTTPEnable"] as? Int == 1)
        #expect(result.settings["HTTPProxy"] as? String == "127.0.0.1")
        #expect(result.settings["HTTPPort"] as? Int == 9999)
        #expect(result.settings["HTTPSEnable"] == nil)
    }

    @Test func restorationIsIdempotent() {
        let original: [String: Any] = ["HTTPEnable": false]
        let first = ProxyPlan.restoration(current: ProxyPlan.installed(on: original), original: original)
        let second = ProxyPlan.restoration(current: first.settings, original: original)
        #expect(NSDictionary(dictionary: first.settings).isEqual(to: second.settings))
        #expect(second.conflicts.isEmpty)
    }

    @Test func journalPreservesCompleteOriginalPropertyList() throws {
        let original: [String: Any] = ["ExceptionsList": ["*.local"], "HTTPEnable": 0, "HTTPProxy": "", "HTTPPort": 0,
                                       "OtherData": Data([1, 2, 3]), "Nested": ["Value": true]]
        let snapshot = try ProxyJournal(serviceID: "test", serviceName: "Wi-Fi ' 테스트", original: original,
                                        ownerUID: 501, appPID: 101, enginePID: 102)
        let decoded = try JSONDecoder().decode(ProxyJournal.self, from: JSONEncoder().encode(snapshot))
        #expect(NSDictionary(dictionary: try decoded.original()).isEqual(to: original))
        #expect(decoded.serviceName == "Wi-Fi ' 테스트")
    }

    @Test func unsafeJournalIsRejected() throws {
        let invalid = try ProxyJournal(serviceID: "", serviceName: "bad", original: [:], ownerUID: 0, appPID: 1, enginePID: 2)
        #expect(throws: VeilError.self) { try invalid.original() }
    }

    @Test func tamperedRestoreValuesAreRejected() {
        #expect(throws: VeilError.self) { try ProxyPlan.validateOriginal(["HTTPEnable": "off"]) }
        #expect(throws: VeilError.self) { try ProxyPlan.validateOriginal(["HTTPPort": 99999]) }
        #expect(throws: VeilError.self) { try ProxyPlan.validateOriginal(["HTTPSProxy": ["unexpected"]]) }
    }
}

@Suite("Privilege command encoding")
struct EscapingTests {
    @Test func shellSingleQuotesPreventExpansion() {
        #expect(CommandEscaping.shell("hello") == "'hello'")
        #expect(CommandEscaping.shell("a'b") == "'a'\\''b'")
        #expect(CommandEscaping.shell("$(touch /tmp/pwn); `id`\nnext") == "'$(touch /tmp/pwn); `id`\nnext'")
    }

    @Test func appleScriptEscapesQuotesSlashesAndLines() {
        #expect(CommandEscaping.appleScript("a\"b\\c\nd\re") == "\"a\\\"b\\\\c\\nd\\re\"")
    }

    #if os(macOS)
    @Test(arguments: ["Wi-Fi", "한글 네트워크", "a'b", "$(echo injected)", "`whoami`", "x; exit 1", "line\nbreak", "double\"quote"])
    func shellRoundTripsAdversarialArguments(value: String) throws {
        let process = Process(), stdout = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf '%s' " + CommandEscaping.shell(value)]
        process.standardOutput = stdout
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        #expect(String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) == value)
    }

    @Test func appleScriptShellRoundTripWithoutPrivilege() throws {
        let value = "apostrophe' quote\" slash\\ $(echo pwn) ; \n한글"
        let shell = "/usr/bin/printf '%s' " + CommandEscaping.shell(value)
        let process = Process(), stdout = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "do shell script " + CommandEscaping.appleScript(shell) + " without altering line endings"]
        process.standardOutput = stdout
        try process.run(); process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        let output = String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(output == value + "\n")
    }
    #endif
}

#if os(macOS)
@Suite("Active network selection")
struct NetworkSelectionTests {
    @Test func newSelectionPrefersActiveServiceOverAlphabeticalBridge() {
        #expect(SystemProxy.preferredServiceID(available: ["bridge", "wifi"], saved: "", primary: "wifi") == "wifi")
    }

    @Test func validManualSelectionIsPreservedUntilExplicitActiveRefresh() {
        #expect(SystemProxy.preferredServiceID(available: ["ethernet", "wifi"], saved: "ethernet", primary: "wifi") == "ethernet")
        #expect(SystemProxy.preferredServiceID(available: ["ethernet", "wifi"], saved: "ethernet", primary: "wifi", preferPrimary: true) == "wifi")
    }

    @Test func missingOrUnavailablePrimaryDoesNotProduceInvalidSelection() {
        #expect(SystemProxy.preferredServiceID(available: ["wifi"], saved: "removed", primary: "vpn") == "wifi")
        #expect(SystemProxy.preferredServiceID(available: [], saved: "removed", primary: "wifi") == "")
        #expect(SystemProxy.preferredServiceID(available: ["wifi"], saved: "", primary: nil) == "wifi")
    }
}
#endif
