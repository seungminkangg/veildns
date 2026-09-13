import Foundation
import Darwin
import VeilDNSCore

@main
struct ProxyHelper {
    static func main() {
        do {
            let arguments = CommandLine.arguments
            guard geteuid() == 0, arguments.count == 4,
                  ["watch", "restore"].contains(arguments[1]), let owner = UInt32(arguments[2]), owner != 0 else {
                throw VeilError.message("이 도우미는 VeilDNS의 네트워크 설정에만 사용할 수 있습니다.")
            }
            let journal = try SecureFiles.readJournal(path: arguments[3], ownerUID: owner)
            if arguments[1] == "restore" {
                let conflicts = try SystemProxy.restore(journal)
                try emit(conflicts: conflicts)
                return
            }

            // Register exit observation BEFORE applying settings. kqueue follows these process instances,
            // avoiding PID reuse races and automatically covering force-quit and engine failures.
            let queue = kqueue()
            guard queue >= 0 else { throw VeilError.message("프로세스 종료 감시를 시작할 수 없습니다.") }
            defer { close(queue) }
            guard let app = journal.appIdentity, let engine = journal.engineIdentity,
                  app.pid == journal.appPID, engine.pid == journal.enginePID,
                  engine.parentPID == app.pid, app.realUID == owner, engine.realUID == owner,
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
            let conflicts = try SystemProxy.restore(journal)
            try emit(conflicts: conflicts)
        } catch {
            // Only localized, bounded errors leave this helper; journal content never appears in output.
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    private static func emit(conflicts: [String]) throws {
        let data = try JSONSerialization.data(withJSONObject: ["event": "restored", "preserved_changes": conflicts])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    }
}
