import Foundation
import Darwin
import SystemConfiguration
import VeilDNSCore

/// CI-only executable; never bundled in the app. It creates a disabled, unattached network service.
@main
struct IntegrationChecks {
    static func main() {
        do {
            guard ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true" else {
                throw VeilError.message("These privileged integration checks only run on GitHub Actions.")
            }
            if CommandLine.arguments.dropFirst().first == "--sentinel" {
                try sentinel()
                return
            }
            guard geteuid() == 0, let rawOwner = ProcessInfo.processInfo.environment["SUDO_UID"],
                  let owner = UInt32(rawOwner), owner != 0, let user = getpwuid(owner),
                  let homePointer = user.pointee.pw_dir else {
                throw VeilError.message("Run via sudo -E as the non-root CI runner account.")
            }
            let home = String(cString: homePointer)
            let group = user.pointee.pw_gid
            let directory = URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/VeilDNS")
            guard !FileManager.default.fileExists(atPath: directory.path) else {
                throw VeilError.message("Refusing to touch an existing VeilDNS user directory.")
            }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700, .ownerAccountID: owner, .groupOwnerAccountID: group])
            let journalURL = directory.appendingPathComponent("proxy-journal.json")
            defer {
                try? FileManager.default.removeItem(at: journalURL)
                try? FileManager.default.removeItem(at: directory)
            }

            let beforeServices = try SystemProxy.services()
            let before = try Dictionary(uniqueKeysWithValues: beforeServices.map { ($0.id, try SystemProxy.read(serviceID: $0.id)) })
            let originalCurrentSet = try currentSetIDs()
            guard let prefs = SCPreferencesCreate(nil, "VeilDNS isolated integration" as CFString, nil),
                  let interfaces = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface],
                  let interface = interfaces.first(where: { SCNetworkInterfaceGetBSDName($0) != nil }),
                  let service = SCNetworkServiceCreate(prefs, interface),
                  let rawServiceID = SCNetworkServiceGetServiceID(service) else {
                throw VeilError.message("Could not create isolated test service.")
            }
            let serviceID = rawServiceID as String
            var needsServiceCleanup = true
            defer {
                if needsServiceCleanup { try? removeService(serviceID) }
            }
            try require(SCNetworkServiceSetName(service, "VeilDNS CI isolated \(UUID().uuidString)" as CFString), "name isolated service")
            try require(SCNetworkServiceSetEnabled(service, false), "disable isolated service")
            if SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) == nil {
                try require(SCNetworkServiceAddProtocolType(service, kSCNetworkProtocolTypeProxies), "add proxy protocol")
            }
            try require(SCPreferencesCommitChanges(prefs), "persist isolated service")
            try require(SCPreferencesApplyChanges(prefs), "apply isolated service")
            try require(!(try currentSetIDs()).contains(serviceID), "isolated service must not enter current network set")

            for scenario in ["engine-exit", "app-crash", "foreign-edit", "stale-identity"] {
                try runScenario(scenario, serviceID: serviceID, owner: owner, group: group, journalURL: journalURL)
                print("PASS \(scenario)")
            }
            for (id, original) in before {
                try require(NSDictionary(dictionary: try SystemProxy.read(serviceID: id)).isEqual(to: original), "active service proxy settings unchanged")
            }
            try require(try currentSetIDs() == originalCurrentSet, "current network set membership unchanged")
            try removeService(serviceID)
            needsServiceCleanup = false
            try FileManager.default.removeItem(at: journalURL)
            try FileManager.default.removeItem(at: directory)
            try require(!FileManager.default.fileExists(atPath: directory.path), "test recovery directory removed")
            print("PASS active network services unchanged; isolated service and recovery directory removal verified")
        } catch {
            FileHandle.standardError.write(Data(("FAIL " + error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    private static func currentSetIDs() throws -> Set<String> {
        guard let prefs = SCPreferencesCreate(nil, "VeilDNS current-set audit" as CFString, nil),
              let current = SCNetworkSetCopyCurrent(prefs),
              let services = SCNetworkSetCopyServices(current) as? [SCNetworkService] else {
            throw VeilError.message("Cannot inspect the current network set.")
        }
        return Set(services.compactMap { service in
            guard let id = SCNetworkServiceGetServiceID(service) else { return nil }
            return id as String
        })
    }

    private static func removeService(_ serviceID: String) throws {
        guard let cleanup = SCPreferencesCreate(nil, "VeilDNS isolated cleanup" as CFString, nil),
              let service = SCNetworkServiceCopy(cleanup, serviceID as CFString) else {
            throw VeilError.message("Isolated cleanup service is missing.")
        }
        try require(SCPreferencesLock(cleanup, false), "cleanup lock")
        defer { SCPreferencesUnlock(cleanup) }
        try require(SCNetworkServiceRemove(service), "remove isolated service")
        try require(SCPreferencesCommitChanges(cleanup), "commit isolated service removal")
        try require(SCPreferencesApplyChanges(cleanup), "apply isolated service removal")
        guard let verify = SCPreferencesCreate(nil, "VeilDNS cleanup verification" as CFString, nil) else {
            throw VeilError.message("Cannot verify service cleanup.")
        }
        try require(SCNetworkServiceCopy(verify, serviceID as CFString) == nil, "isolated service removal verified")
    }

    private static func sentinel() throws {
        guard geteuid() != 0 else { throw VeilError.message("Sentinel must run as non-root runner.") }
        let child = Process(), lifetime = Pipe()
        child.executableURL = URL(fileURLWithPath: "/bin/cat")
        child.standardInput = lifetime
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        try child.run()
        try? lifetime.fileHandleForReading.close()
        let data = try JSONSerialization.data(withJSONObject: ["app": getpid(), "engine": child.processIdentifier])
        FileHandle.standardOutput.write(data + Data([10]))
        // Keep the pipe alive until killed by the test. The child exits on its parent writer's EOF.
        withExtendedLifetime(lifetime) { while true { pause() } }
    }

    private static func runScenario(_ scenario: String, serviceID: String, owner: uid_t, group: gid_t, journalURL: URL) throws {
        let original: [String: Any] = scenario == "engine-exit"
            ? ["ExceptionsList": ["*.local", "original.example"]]
            : ["HTTPEnable": 0, "HTTPProxy": "old.example", "HTTPPort": 3128,
               "HTTPSEnable": 0, "HTTPSProxy": "", "HTTPSPort": 0,
               "ExceptionsList": ["*.local", "original.example"]]
        try setSettings(original, serviceID: serviceID)
        let launcher = Process(), stdout = Pipe()
        launcher.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        launcher.arguments = ["-E", "-u", "#\(owner)", CommandLine.arguments[0], "--sentinel"]
        launcher.standardInput = FileHandle.nullDevice
        launcher.standardOutput = stdout
        launcher.standardError = FileHandle.standardError
        try launcher.run()
        let line = stdout.fileHandleForReading.availableData
        guard let ids = try JSONSerialization.jsonObject(with: line) as? [String: Int32],
              let appPID = ids["app"], let enginePID = ids["engine"] else {
            throw VeilError.message("Sentinel did not report its child PID.")
        }
        let appIdentity = try ProcessIdentity.capture(appPID)
        let engineIdentity = try ProcessIdentity.capture(enginePID)
        defer {
            if (try? ProcessIdentity.capture(appPID)) == appIdentity { kill(appPID, SIGKILL) }
            if (try? ProcessIdentity.capture(enginePID)) == engineIdentity { kill(enginePID, SIGKILL) }
        }
        let journal = try ProxyJournal(serviceID: serviceID, serviceName: "CI isolated", original: original, ownerUID: owner,
            appPID: appPID, enginePID: enginePID, appIdentity: appIdentity, engineIdentity: engineIdentity)
        var journalData = try JSONEncoder().encode(journal)
        if scenario == "stale-identity" {
            var object = try JSONSerialization.jsonObject(with: journalData) as! [String: Any]
            var identity = object["engineIdentity"] as! [String: Any]
            identity["startSeconds"] = 1
            object["engineIdentity"] = identity
            journalData = try JSONSerialization.data(withJSONObject: object)
        }
        try SecureFiles.write(journalData, to: journalURL)
        try FileManager.default.setAttributes([.ownerAccountID: owner, .groupOwnerAccountID: group, .posixPermissions: 0o600], ofItemAtPath: journalURL.path)
        let helper = Process(), helperOutput = Pipe(), helperError = Pipe()
        helper.executableURL = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("VeilDNSProxyHelper")
        helper.arguments = ["watch", String(owner), journalURL.path]
        helper.standardOutput = helperOutput
        helper.standardError = helperError
        try helper.run()
        defer { if helper.isRunning { helper.terminate() } }
        if scenario == "stale-identity" {
            try waitUntil("stale identity rejection") { !helper.isRunning }
            try require(helper.terminationStatus != 0, "reject reused identity")
            try require(NSDictionary(dictionary: try SystemProxy.read(serviceID: serviceID)).isEqual(to: original), "stale identity cannot change proxy")
            return
        }
        try waitUntil("proxy apply") {
            if !helper.isRunning {
                throw VeilError.message("Helper failed: " + String(decoding: helperError.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
            }
            return ProxyPlan.isOwned(try SystemProxy.read(serviceID: serviceID), original: original)
        }
        var expected = original
        if scenario == "foreign-edit" {
            var changed = try SystemProxy.read(serviceID: serviceID)
            changed["ExceptionsList"] = ["foreign.example"]
            changed["HTTPPort"] = 9999
            try setSettings(changed, serviceID: serviceID)
            expected = ProxyPlan.restoration(current: changed, original: original).settings
        }
        let target = scenario == "app-crash" ? appPID : enginePID
        try require(kill(target, SIGKILL) == 0, "stop watched process")
        try waitUntil("watcher restoration") { !helper.isRunning }
        try require(helper.terminationStatus == 0, "helper exits successfully")
        try require(NSDictionary(dictionary: try SystemProxy.read(serviceID: serviceID)).isEqual(to: expected), "exact restoration and foreign edits preservation")
        if scenario == "app-crash" {
            try waitUntil("orphan engine EOF exit") { (try? ProcessIdentity.capture(enginePID)) == nil }
        }
        let output = helperOutput.fileHandleForReading.readDataToEndOfFile()
        let event = try JSONSerialization.jsonObject(with: output) as? [String: Any]
        try require(event?["event"] as? String == "restored", "restoration receipt")
    }

    private static func setSettings(_ settings: [String: Any], serviceID: String) throws {
        guard let prefs = SCPreferencesCreate(nil, "VeilDNS isolated fixture" as CFString, nil),
              let service = SCNetworkServiceCopy(prefs, serviceID as CFString),
              let proxy = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
            throw VeilError.message("Isolated fixture service disappeared.")
        }
        try require(SCPreferencesLock(prefs, false), "fixture lock")
        defer { SCPreferencesUnlock(prefs) }
        try require(SCNetworkProtocolSetConfiguration(proxy, settings as CFDictionary), "set isolated fixture")
        try require(SCPreferencesCommitChanges(prefs), "commit isolated fixture")
        try require(SCPreferencesApplyChanges(prefs), "apply isolated fixture")
    }

    private static func waitUntil(_ label: String, _ condition: () throws -> Bool) throws {
        for _ in 0..<100 {
            if try condition() { return }
            usleep(100_000)
        }
        throw VeilError.message("Timed out: \(label)")
    }

    private static func require(_ condition: Bool, _ label: String) throws {
        if !condition { throw VeilError.message(label) }
    }
}
