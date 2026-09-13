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
    let exitCode: Int32
    let output: String
    let error: String

    var restored: Bool {
        guard exitCode == 0, let data = output.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return object["event"] as? String == "restored"
    }

    var preservedChanges: [String] {
        guard let data = output.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        return object["preserved_changes"] as? [String] ?? []
    }
}

enum HelperProcess {
    static func run(operation: String) async throws -> HelperResult {
        guard let helper = Bundle.main.resourceURL?.appendingPathComponent("VeilDNSProxyHelper"),
              FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw VeilError.message("네트워크 복구 도우미가 앱에 없습니다. 완성된 앱 번들을 사용해 주세요.")
        }
        let script = CommandEscaping.privilegedInvocation(executable: helper.path,
            arguments: [operation, String(getuid()), SecureFiles.journalURL.path])
        return try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            let stdout = Pipe(), stderr = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = stdout
            process.standardError = stderr
            process.terminationHandler = { child in
                let output = stdout.fileHandleForReading.readDataToEndOfFile()
                let error = stderr.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: HelperResult(exitCode: child.terminationStatus,
                    output: String(decoding: output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
                    error: String(decoding: error.suffix(4000), as: UTF8.self)))
            }
            do { try process.run() }
            catch { continuation.resume(throwing: error) }
        }
    }
}
