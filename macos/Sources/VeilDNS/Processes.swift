@preconcurrency import Foundation
import Darwin
import VeilDNSCore

@MainActor
final class EngineProcess {
    private var process: Process?
    private var output = Data()
    private var errorOutput = Data()
    private var ready = false
    private var lifetimePipe: Pipe?
    private var generation = UUID()
    var onExit: (@MainActor () -> Void)?
    var pid: pid_t { process?.processIdentifier ?? 0 }
    var isRunning: Bool { process?.isRunning == true }

    func start(configurationURL: URL) async throws {
        guard let resource = Bundle.main.resourceURL?.appendingPathComponent("veildns-engine"),
              FileManager.default.isExecutableFile(atPath: resource.path) else {
            throw VeilError.message("앱에 네트워크 엔진이 포함되어 있지 않습니다. 완성된 VeilDNS.app 번들을 사용해 주세요.")
        }
        output.removeAll(); errorOutput.removeAll(); ready = false
        let generation = UUID()
        self.generation = generation
        let child = Process()
        let stdout = Pipe(), stderr = Pipe(), lifetime = Pipe()
        child.executableURL = resource
        child.arguments = ["--config", configurationURL.path, "--exit-on-stdin-close"]
        child.standardInput = lifetime
        lifetimePipe = lifetime
        child.standardOutput = stdout
        child.standardError = stderr
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            Task { @MainActor in self?.receive(data, generation: generation) }
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            Task { @MainActor in
                guard let self, self.generation == generation else { return }
                self.errorOutput.append(data)
                if self.errorOutput.count > 8192 { self.errorOutput = Data(self.errorOutput.suffix(8192)) }
            }
        }
        child.terminationHandler = { [weak self] _ in
            Task { @MainActor in
                guard let self, self.generation == generation else { return }
                self.onExit?()
            }
        }
        process = child
        try child.run()
        try? lifetime.fileHandleForReading.close()
        for _ in 0..<200 {
            guard child.isRunning else {
                throw VeilError.message("네트워크 엔진을 시작하지 못했습니다. 포트 8080 사용 여부를 확인해 주세요.\n" + String(decoding: errorOutput.suffix(2000), as: UTF8.self))
            }
            if ready { return }
            try await Task.sleep(for: .milliseconds(100))
        }
        await stop()
        throw VeilError.message("엔진 준비 응답을 받지 못해 시작을 중단했습니다.")
    }

    private func receive(_ data: Data, generation: UUID) {
        guard self.generation == generation else { return }
        output.append(data)
        while let newline = output.firstIndex(of: 10) {
            let line = output[..<newline]
            output.removeSubrange(...newline)
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                  object["event"] as? String == "ready",
                  object["listen"] as? String == "127.0.0.1:8080" else { continue }
            ready = true
        }
        if output.count > 65_536 { output.removeAll() }
    }

    func stop() async {
        try? lifetimePipe?.fileHandleForWriting.close()
        lifetimePipe = nil
        guard let child = process, child.isRunning else { return }
        for _ in 0..<50 {
            if !child.isRunning { return }
            try? await Task.sleep(for: .milliseconds(100))
        }
        if child.isRunning { child.terminate() }
        for _ in 0..<20 {
            if !child.isRunning { return }
            try? await Task.sleep(for: .milliseconds(100))
        }
        if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        for _ in 0..<20 {
            if !child.isRunning { return }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }
}

struct HelperResult: Sendable {
    let restored: Bool
    let preservedChanges: [String]
    let error: String

    init(_ response: PrivilegedChannel.Response) {
        restored = response.event == "restored"
        preservedChanges = response.preservedChanges
        error = response.error
    }
}

/// Talks to the persistent privileged daemon, asking for authorization only when it must be installed.
enum HelperProcess {
    static func run(operation: String) async throws -> HelperResult {
        try await ensureInstalled()
        return HelperResult(try await background { try exchange(operation: operation, timeout: nil) })
    }

    /// True when a daemon of this exact protocol version is already answering.
    static func isInstalled() async -> Bool {
        guard let response = try? await background({ try exchange(operation: "status", timeout: 5) }) else { return false }
        return response.event == "ready" && response.version == PrivilegedChannel.version
    }

    static func uninstall() async throws {
        let response = try await background { try exchange(operation: "uninstall", timeout: 20) }
        guard response.event == "uninstalled" else {
            throw VeilError.message(response.error.isEmpty ? "네트워크 도우미를 제거하지 못했습니다." : response.error)
        }
    }

    private static func ensureInstalled() async throws {
        if await isInstalled() { return }
        try await authorizeInstall()
        for _ in 0..<100 {
            if await isInstalled() { return }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw VeilError.message("네트워크 도우미가 시작되지 않았습니다. 다시 시도해 주세요.")
    }

    /// The only step that shows the macOS authorization dialog. It runs once per install or version change.
    private static func authorizeInstall() async throws {
        guard let helper = Bundle.main.resourceURL?.appendingPathComponent("VeilDNSProxyHelper"),
              FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw VeilError.message("네트워크 복구 도우미가 앱에 없습니다. 완성된 앱 번들을 사용해 주세요.")
        }
        let script = CommandEscaping.privilegedInvocation(executable: helper.path,
            arguments: ["install", String(getuid())])
        let failure: String = try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            let stderr = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = stderr
            process.terminationHandler = { child in
                let error = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile().suffix(4000), as: UTF8.self)
                continuation.resume(returning: child.terminationStatus == 0 ? "" : error)
            }
            do { try process.run() }
            catch { continuation.resume(throwing: error) }
        }
        guard failure.isEmpty else {
            throw VeilError.message(failure.contains("-128") ? "네트워크 도우미 설치가 취소되었습니다." : failure)
        }
    }

    private static func exchange(operation: String, timeout: Int?) throws -> PrivilegedChannel.Response {
        guard let fd = try PrivilegedChannel.connect() else {
            throw VeilError.message("설치된 네트워크 도우미가 없습니다.")
        }
        defer { close(fd) }
        if let timeout {
            // A watch session owns the daemon; short requests must not hang the interface behind it.
            var limit = timeval(tv_sec: timeout, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        }
        try PrivilegedChannel.write(try JSONEncoder().encode(PrivilegedChannel.Request(operation: operation)), to: fd)
        guard let raw = try PrivilegedChannel.readMessage(fd) else {
            throw VeilError.message("네트워크 도우미와의 연결이 끊어졌습니다.")
        }
        return try JSONDecoder().decode(PrivilegedChannel.Response.self, from: raw)
    }

    private static func background<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do { continuation.resume(returning: try work()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}
