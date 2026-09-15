#if os(macOS)
import Foundation
import Darwin

/// Names and framing shared by the app and the privileged helper.
///
/// The persistent daemon exists so a user authorizes VeilDNS once instead of on every connection.
/// That trade is deliberate and bounded: the daemon only ever performs the same scoped proxy apply
/// and restore the on-demand helper performs, it reads one fixed recovery record owned by the
/// installing account, and it refuses every peer whose effective UID is not that account.
public enum PrivilegedChannel {
    public static let label = "io.github.seungminkangg.veildns.helper"
    public static let toolPath = "/Library/PrivilegedHelperTools/\(label)"
    public static let daemonPath = "/Library/LaunchDaemons/\(label).plist"
    public static let socketDirectory = "/var/run/veildns"
    public static let socketPath = "\(socketDirectory)/helper.sock"
    /// Bumped whenever the installed tool must be replaced. A mismatch costs one authorization dialog.
    public static let version = 1
    /// Bounds a single newline-delimited message so neither side can be driven to allocate.
    static let messageLimit = 64 * 1024

    public struct Request: Codable, Sendable {
        public let operation: String
        public init(operation: String) { self.operation = operation }
    }

    public struct Response: Codable, Sendable {
        public let event: String
        public let preservedChanges: [String]
        public let error: String
        public let version: Int

        public init(event: String, preservedChanges: [String] = [], error: String = "", version: Int = PrivilegedChannel.version) {
            self.event = event
            self.preservedChanges = preservedChanges
            self.error = error
            self.version = version
        }

        enum CodingKeys: String, CodingKey {
            case event, preservedChanges = "preserved_changes", error, version
        }
    }

    public static func socketAddress() throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8)
        // sun_path must stay NUL-terminated inside its fixed-size buffer.
        guard path.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw VeilError.message("도우미 소켓 경로가 너무 깁니다.")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: path)
            buffer[path.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }

    /// Connects to an installed daemon. Returns nil when no daemon is listening yet.
    public static func connect() throws -> Int32? {
        var address = try socketAddress()
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw VeilError.message("도우미 소켓을 열 수 없습니다.") }
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                Darwin.connect(fd, raw, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connected == 0 { return fd }
        let failure = errno
        close(fd)
        // A missing or unattended socket means "not installed yet"; anything else is a real fault.
        guard [ENOENT, ECONNREFUSED, ENOTDIR].contains(failure) else {
            throw VeilError.message("네트워크 도우미에 연결하지 못했습니다. (\(String(cString: strerror(failure))))")
        }
        return nil
    }

    /// Effective UID of the connected peer. Used to reject every account but the installer.
    public static func peerUID(_ fd: Int32) throws -> uid_t {
        var uid = uid_t(0), gid = gid_t(0)
        guard getpeereid(fd, &uid, &gid) == 0 else {
            throw VeilError.message("연결한 사용자를 확인할 수 없습니다.")
        }
        return uid
    }

    public static func write(_ data: Data, to fd: Int32) throws {
        var payload = data
        payload.append(10)
        try payload.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw VeilError.message("도우미와의 통신이 끊어졌습니다.") }
                offset += count
            }
        }
    }

    /// Reads one newline-delimited message. Returns nil when the peer closes first.
    public static func readMessage(_ fd: Int32) throws -> Data? {
        var buffer = Data()
        var byte: UInt8 = 0
        while buffer.count <= messageLimit {
            let count = Darwin.read(fd, &byte, 1)
            if count < 0 && errno == EINTR { continue }
            if count == 0 { return buffer.isEmpty ? nil : buffer }
            guard count > 0 else { throw VeilError.message("도우미 응답을 읽지 못했습니다.") }
            if byte == 10 { return buffer }
            buffer.append(byte)
        }
        throw VeilError.message("도우미 메시지가 허용된 크기를 넘었습니다.")
    }

    /// The daemon derives this from the verified peer UID; a client never names the file it reads.
    public static func journalPath(ownerUID: uid_t) throws -> String {
        guard ownerUID != 0, let user = getpwuid(ownerUID), let home = user.pointee.pw_dir else {
            throw VeilError.message("복구 기록의 소유자를 확인할 수 없습니다.")
        }
        return URL(fileURLWithPath: String(cString: home))
            .appendingPathComponent("Library/Application Support/VeilDNS/proxy-journal.json").path
    }
}
#endif
