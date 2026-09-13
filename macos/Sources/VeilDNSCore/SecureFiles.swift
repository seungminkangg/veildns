#if os(macOS)
import Foundation
import Darwin

public enum SecureFiles {
    public static var directory: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/VeilDNS", isDirectory: true)
    }
    public static var journalURL: URL { directory.appendingPathComponent("proxy-journal.json") }

    public static func prepareDirectory() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard directory.standardizedFileURL.path == directory.resolvingSymlinksInPath().standardizedFileURL.path else {
            throw VeilError.message("VeilDNS 설정 폴더에는 심볼릭 링크를 사용할 수 없습니다.")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    public static func write(_ data: Data, to url: URL) throws {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".\(UUID().uuidString).tmp")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw VeilError.message("설정 파일을 안전하게 만들 수 없습니다.") }
        defer { close(fd); unlink(temporary.path) }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw VeilError.message("설정 파일을 저장하지 못했습니다.") }
                offset += count
            }
        }
        guard fsync(fd) == 0, rename(temporary.path, url.path) == 0 else {
            throw VeilError.message("설정 파일을 디스크에 기록하지 못했습니다.")
        }
        let directoryFD = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY)
        defer { if directoryFD >= 0 { close(directoryFD) } }
        guard directoryFD >= 0, fsync(directoryFD) == 0 else {
            throw VeilError.message("설정 폴더를 디스크에 기록하지 못했습니다.")
        }
    }

    /// The root helper only reads one fixed, owner-controlled recovery record. It never writes user paths.
    public static func readJournal(path: String, ownerUID: uid_t) throws -> ProxyJournal {
        guard ownerUID != 0, let user = getpwuid(ownerUID), let homePointer = user.pointee.pw_dir else {
            throw VeilError.message("복구 기록의 소유자를 확인할 수 없습니다.")
        }
        let home = String(cString: homePointer)
        let expected = URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/VeilDNS/proxy-journal.json")
        let actual = URL(fileURLWithPath: path)
        guard actual.standardizedFileURL.path == expected.standardizedFileURL.path,
              actual.resolvingSymlinksInPath().path == expected.standardizedFileURL.path else {
            throw VeilError.message("허용되지 않은 복구 기록 경로입니다.")
        }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw VeilError.message("복구 기록을 열 수 없습니다.") }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == ownerUID,
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o777 == 0o600,
              info.st_nlink == 1, info.st_size > 0, info.st_size <= 1_048_576 else {
            throw VeilError.message("복구 기록의 파일 권한 또는 크기가 올바르지 않습니다.")
        }
        var data = Data(count: Int(info.st_size))
        try data.withUnsafeMutableBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.read(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw VeilError.message("복구 기록을 읽지 못했습니다.") }
                offset += count
            }
        }
        let journal = try JSONDecoder().decode(ProxyJournal.self, from: data)
        guard journal.ownerUID == ownerUID else { throw VeilError.message("복구 기록의 소유자가 일치하지 않습니다.") }
        _ = try journal.original()
        return journal
    }
}
#endif
