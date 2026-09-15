import Foundation
import Darwin
import VeilDNSCore

@main
struct ProxyHelper {
    static func main() {
        do {
            let arguments = CommandLine.arguments
            guard geteuid() == 0, arguments.count >= 2 else {
                throw VeilError.message("이 도우미는 VeilDNS의 네트워크 설정에만 사용할 수 있습니다.")
            }
            switch arguments[1] {
            case "watch", "restore":
                // Direct invocation under a one-shot authorization dialog, and the path CI exercises.
                guard arguments.count == 4, let owner = UInt32(arguments[2]), owner != 0 else {
                    throw VeilError.message("이 도우미는 VeilDNS의 네트워크 설정에만 사용할 수 있습니다.")
                }
                let journal = try SecureFiles.readJournal(path: arguments[3], ownerUID: owner)
                let conflicts = arguments[1] == "restore" ? try restore(journal) : try watch(journal)
                try emit(.init(event: "restored", preservedChanges: conflicts))
            case "install":
                guard arguments.count == 3, let owner = UInt32(arguments[2]), owner != 0 else {
                    throw VeilError.message("이 도우미는 VeilDNS의 네트워크 설정에만 사용할 수 있습니다.")
                }
                try install(ownerUID: owner)
                try emit(.init(event: "installed"))
            case "daemon":
                guard arguments.count == 3, let owner = UInt32(arguments[2]), owner != 0 else {
                    throw VeilError.message("이 도우미는 VeilDNS의 네트워크 설정에만 사용할 수 있습니다.")
                }
                try serve(ownerUID: owner)
            case "uninstall":
                try uninstall()
                try emit(.init(event: "uninstalled"))
            default:
                throw VeilError.message("이 도우미는 VeilDNS의 네트워크 설정에만 사용할 수 있습니다.")
            }
        } catch {
            // Only localized, bounded errors leave this helper; journal content never appears in output.
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    // MARK: - Scoped proxy session

    private static func restore(_ journal: ProxyJournal) throws -> [String] {
        try SystemProxy.restore(journal)
    }

    /// Applies the journal, then holds until the recorded app or engine exits and restores exactly what it owns.
    private static func watch(_ journal: ProxyJournal) throws -> [String] {
        // Register exit observation BEFORE applying settings. kqueue follows these process instances,
        // avoiding PID reuse races and automatically covering force-quit and engine failures.
        let queue = kqueue()
        guard queue >= 0 else { throw VeilError.message("프로세스 종료 감시를 시작할 수 없습니다.") }
        defer { close(queue) }
        guard let app = journal.appIdentity, let engine = journal.engineIdentity,
              app.pid == journal.appPID, engine.pid == journal.enginePID,
              engine.parentPID == app.pid, app.realUID == journal.ownerUID, engine.realUID == journal.ownerUID,
              app.startSeconds > 0, engine.startSeconds > 0 else {
            throw VeilError.message("앱과 엔진의 실행 정보를 확인할 수 없습니다.")
        }
        for identity in [app, engine] {
            let pid = identity.pid
            guard try ProcessIdentity.capture(pid) == identity else {
                throw VeilError.message("권한 승인 중 프로세스가 변경되어 적용을 중단했습니다.")
            }
            var change = kevent(ident: UInt(pid), filter: Int16(EVFILT_PROC), flags: UInt16(EV_ADD | EV_ENABLE | EV_ONESHOT), fflags: NOTE_EXIT, data: 0, udata: nil)
            guard kevent(queue, &change, 1, nil, 0, nil) >= 0 else {
                throw VeilError.message("앱 또는 엔진이 이미 종료되었습니다.")
            }
            guard try ProcessIdentity.capture(pid) == identity else {
                throw VeilError.message("종료 감시 등록 중 프로세스가 변경되었습니다.")
            }
        }
        var event = kevent()
        var immediate = timespec(tv_sec: 0, tv_nsec: 0)
        guard kevent(queue, nil, 0, &event, 1, &immediate) == 0 else {
            throw VeilError.message("앱 또는 엔진이 이미 종료되었습니다.")
        }
        do {
            try SystemProxy.apply(journal)
            while true {
                let count = kevent(queue, nil, 0, &event, 1, nil)
                if count > 0 { break }
                if count < 0 && errno == EINTR { continue }
                if count < 0 { throw VeilError.message("종료 감시에 실패하여 프록시를 복구합니다.") }
            }
        } catch {
            // A commit can precede an apply failure. Always attempt scoped CAS restoration.
            _ = try? SystemProxy.restore(journal)
            throw error
        }
        return try SystemProxy.restore(journal)
    }

    // MARK: - Persistent authorization

    /// Installs the launchd job so later sessions need no authorization dialog.
    private static func install(ownerUID: uid_t) throws {
        let source = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        var sourceInfo = stat()
        guard stat(source.path, &sourceInfo) == 0, sourceInfo.st_mode & S_IFMT == S_IFREG else {
            throw VeilError.message("설치할 도우미 실행 파일을 찾을 수 없습니다.")
        }
        // An already-running job must release the socket before its binary is replaced.
        _ = launchctl(["bootout", "system/\(PrivilegedChannel.label)"])
        let tool = URL(fileURLWithPath: PrivilegedChannel.toolPath)
        try FileManager.default.createDirectory(at: tool.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755, .ownerAccountID: 0, .groupOwnerAccountID: 0])
        if FileManager.default.fileExists(atPath: tool.path) { try FileManager.default.removeItem(at: tool) }
        try FileManager.default.copyItem(at: source, to: tool)
        try FileManager.default.setAttributes([.posixPermissions: 0o755, .ownerAccountID: 0, .groupOwnerAccountID: 0],
            ofItemAtPath: tool.path)
        // A bundle unpacked from a download carries quarantine; launchd will not start a quarantined daemon.
        removexattr(tool.path, "com.apple.quarantine", 0)

        let job: [String: Any] = [
            "Label": PrivilegedChannel.label,
            "ProgramArguments": [tool.path, "daemon", String(ownerUID)],
            "RunAtLoad": true,
            // Restart after a crash, but let a deliberate exit during uninstall stay down.
            "KeepAlive": ["SuccessfulExit": false],
            "AbandonProcessGroup": false,
            "ProcessType": "Background",
        ]
        let plist = try PropertyListSerialization.data(fromPropertyList: job, format: .xml, options: 0)
        try plist.write(to: URL(fileURLWithPath: PrivilegedChannel.daemonPath), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644, .ownerAccountID: 0, .groupOwnerAccountID: 0],
            ofItemAtPath: PrivilegedChannel.daemonPath)
        guard launchctl(["bootstrap", "system", PrivilegedChannel.daemonPath]) == 0 else {
            throw VeilError.message("네트워크 도우미를 등록하지 못했습니다.")
        }
        for _ in 0..<100 {
            var info = stat()
            if stat(PrivilegedChannel.socketPath, &info) == 0 { return }
            usleep(100_000)
        }
        throw VeilError.message("네트워크 도우미가 시작되지 않았습니다.")
    }

    private static func uninstall() throws {
        try? FileManager.default.removeItem(atPath: PrivilegedChannel.daemonPath)
        try? FileManager.default.removeItem(atPath: PrivilegedChannel.toolPath)
        unlink(PrivilegedChannel.socketPath)
    }

    /// Only one proxy session may own the network settings at a time.
    nonisolated(unsafe) private static var sessionLock = pthread_mutex_t()

    private static func withSession<T>(_ work: () throws -> T) throws -> T {
        guard pthread_mutex_trylock(&sessionLock) == 0 else {
            throw VeilError.message("이미 진행 중인 네트워크 세션이 있습니다.")
        }
        defer { pthread_mutex_unlock(&sessionLock) }
        return try work()
    }

    /// Accepts clients concurrently; a watch session holds only the session lock, not the listener.
    private static func serve(ownerUID: uid_t) throws {
        signal(SIGPIPE, SIG_IGN)
        pthread_mutex_init(&sessionLock, nil)
        try FileManager.default.createDirectory(atPath: PrivilegedChannel.socketDirectory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755, .ownerAccountID: 0, .groupOwnerAccountID: 0])
        unlink(PrivilegedChannel.socketPath)
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw VeilError.message("도우미 소켓을 열 수 없습니다.") }
        defer { close(listener) }
        var address = try PrivilegedChannel.socketAddress()
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                bind(listener, raw, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0 else { throw VeilError.message("도우미 소켓을 준비하지 못했습니다.") }
        // Only the installing account may reach the daemon, enforced by mode and by peer credentials.
        guard chown(PrivilegedChannel.socketPath, ownerUID, 0) == 0,
              chmod(PrivilegedChannel.socketPath, 0o600) == 0, listen(listener, 4) == 0 else {
            throw VeilError.message("도우미 소켓 권한을 설정하지 못했습니다.")
        }
        while true {
            let client = accept(listener, nil, nil)
            if client < 0 {
                if errno == EINTR || errno == ECONNABORTED { continue }
                throw VeilError.message("도우미 연결을 수락하지 못했습니다.")
            }
            let thread = Thread { handle(client, ownerUID: ownerUID); close(client) }
            thread.stackSize = 512 * 1024
            thread.start()
        }
    }

    private static func handle(_ client: Int32, ownerUID: uid_t) {
        do {
            guard try PrivilegedChannel.peerUID(client) == ownerUID else {
                throw VeilError.message("이 네트워크 도우미는 설치한 사용자만 사용할 수 있습니다.")
            }
            guard let raw = try PrivilegedChannel.readMessage(client) else { return }
            let request = try JSONDecoder().decode(PrivilegedChannel.Request.self, from: raw)
            let response: PrivilegedChannel.Response
            switch request.operation {
            case "watch", "restore":
                // The client never names a file. The path comes from the verified peer identity.
                let journal = try SecureFiles.readJournal(path: try PrivilegedChannel.journalPath(ownerUID: ownerUID),
                                                          ownerUID: ownerUID)
                let conflicts = try withSession {
                    request.operation == "restore" ? try restore(journal) : try watch(journal)
                }
                response = .init(event: "restored", preservedChanges: conflicts)
            case "status":
                response = .init(event: "ready")
            case "uninstall":
                try uninstall()
                try? PrivilegedChannel.write(try JSONEncoder().encode(PrivilegedChannel.Response(event: "uninstalled")), to: client)
                close(client)
                // Leaving with a successful status keeps KeepAlive from restarting a removed job.
                _ = launchctl(["bootout", "system/\(PrivilegedChannel.label)"])
                exit(0)
            default:
                throw VeilError.message("지원하지 않는 도우미 요청입니다.")
            }
            try PrivilegedChannel.write(try JSONEncoder().encode(response), to: client)
        } catch {
            let failure = PrivilegedChannel.Response(event: "failed", error: error.localizedDescription)
            try? PrivilegedChannel.write((try? JSONEncoder().encode(failure)) ?? Data(), to: client)
        }
    }

    @discardableResult
    private static func launchctl(_ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return -1 }
        process.waitUntilExit()
        return process.terminationStatus
    }

    private static func emit(_ response: PrivilegedChannel.Response) throws {
        FileHandle.standardOutput.write(try JSONEncoder().encode(response))
        FileHandle.standardOutput.write(Data([10]))
    }
}
