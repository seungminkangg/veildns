import Foundation
#if os(macOS)
import Darwin
#endif

public struct ProcessIdentity: Codable, Equatable, Sendable {
    public let pid: Int32
    public let realUID: UInt32
    public let parentPID: Int32
    public let startSeconds: Int64
    public let startMicroseconds: Int32

    #if os(macOS)
    public static func capture(_ pid: pid_t) throws -> ProcessIdentity {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var length = MemoryLayout<kinfo_proc>.size
        let result = mib.withUnsafeMutableBufferPointer { buffer in
            sysctl(buffer.baseAddress, UInt32(buffer.count), &info, &length, nil, 0)
        }
        guard pid > 1, result == 0, length == MemoryLayout<kinfo_proc>.size,
              Int32(info.kp_proc.p_stat) != SZOMB else {
            throw VeilError.message("프로세스 실행 정보를 확인할 수 없습니다.")
        }
        return .init(pid: pid, realUID: info.kp_eproc.e_pcred.p_ruid, parentPID: info.kp_eproc.e_ppid,
                     startSeconds: Int64(info.kp_proc.p_un.__p_starttime.tv_sec),
                     startMicroseconds: Int32(info.kp_proc.p_un.__p_starttime.tv_usec))
    }
    #endif
}
