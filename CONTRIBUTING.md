# 기여 안내

맥에서 암호화 DNS를 제대로 쓰기 어렵다는 문제 하나를 풀려는 프로젝트입니다.
Swift를 몰라도, Rust를 몰라도 도울 수 있는 부분이 있습니다.

## 지금 가장 필요한 것

**1. 실환경 제보 (코드 없이 가능, 가장 중요)**

CI는 GitHub 러너에서만 돕니다. 실제 맥·통신사·브라우저 조합은 검증된 적이 없습니다.
[이슈](https://github.com/seungminkangg/veildns/issues)에 다음을 적어주세요.

- macOS 버전, 칩(Apple Silicon / Intel), 통신사, 브라우저
- 분할 모드(전체 / 지정 목록 / 끄기)와 DNS 제공자
- 무엇이 됐고 무엇이 안 됐는지

접속한 사이트 이름이나 브라우징 기록은 적지 마세요. 필요 없습니다.

**2. 확인된 한계 좁히기**

[docs/VALIDATION.md](docs/VALIDATION.md)의 "Not established by these checks" 목록이 곧 할 일 목록입니다.
재부팅 후 데몬 유지, macOS 15 실제 동작, VPN 공존, 네트워크 전환, DNS 프로파일 실제 라우팅 — 전부 열려 있습니다.

**3. 코드**

처음 손대기 좋은 곳:

| 난이도 | 내용 | 시작 지점 |
| --- | --- | --- |
| 쉬움 | 오류 메시지 문구 개선 (한국어) | `macos/Sources/VeilDNSCore/Settings.swift` |
| 쉬움 | 도메인 규칙 파서 엣지 케이스 테스트 추가 | `engine/src/config.rs` 하단 `mod tests` |
| 보통 | DoH 제공자 추가 (Quad9 등) | `engine/src/dns.rs`의 `DohResolver::new` |
| 보통 | 사용자 지정 DNS 서버 입력 | `Settings.swift` + `config.rs` 양쪽 |
| 어려움 | 분할 전략 옵션 (분할 위치·횟수) | `engine/src/tls.rs` |

## 저장소 구조

```text
macos/Sources/VeilDNS/          SwiftUI 앱, 상태 기계(AppModel), 엔진·도우미 프로세스 관리
macos/Sources/VeilDNSCore/      설정 모델, 프록시 복구 계획, 권한 채널, 안전한 파일 I/O
macos/Sources/VeilDNSProxyHelper/  root 권한 도우미. launchd 데몬 모드 포함
macos/Sources/VeilDNSIntegrationChecks/  CI 전용. 격리된 네트워크 서비스로 실제 시나리오 검증
engine/src/                     Tokio/Hyper 프록시, DoH 클라이언트, TLS ClientHello 파서
scripts/                        패키징, 라이선스 고지 생성, 실제 HTTPS 스모크
```

읽는 순서를 추천하면 `engine/src/config.rs` → `engine/src/tls.rs` → `macos/Sources/VeilDNS/AppModel.swift` 입니다.

## 개발 환경

- **전체 Xcode 26.6 이상이 필요합니다.** Command Line Tools만 있으면 `swift build`는 되지만
  `swift test`가 `no such module 'Testing'`으로 실패합니다. swift-testing은 Xcode에만 들어 있습니다.
- Rust는 `rust-toolchain.toml`이 1.98.1로 고정합니다. [rustup](https://rustup.rs/)만 설치하면 자동으로 맞춥니다.

## PR 전에 돌릴 것

```bash
cargo fmt --manifest-path engine/Cargo.toml --check
cargo clippy --manifest-path engine/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path engine/Cargo.toml --locked
swift test --package-path macos
bash scripts/build-macos.sh
python3 scripts/smoke-proxy.py build/VeilDNS.app/Contents/Resources/veildns-engine
```

권한 도우미 시나리오는 GitHub Actions에서만 돕니다. 로컬에서 실행되지 않아도 정상입니다.

## 리뷰 기준

변경 범위를 좁게 유지하고, 사용자에게 보이는 문제가 무엇이었는지 설명해 주세요.

- 파서를 바꾸면 깨진 입력·잘린 입력과 바이트 보존 테스트가 필요합니다.
- 프록시 수명주기를 바꾸면 복구·충돌·실패·크래시 경로 테스트가 필요합니다.
- 다음은 협상 대상이 아닙니다: loopback 전용 바인딩, 인증서 검증, 자원 상한,
  end-to-end TLS 유지, 일반 프로세스와 권한 프로세스의 분리.
- 권한 도우미를 건드리는 PR은 왜 그 권한이 필요한지, 무엇을 거부하는지 함께 써주세요.

**과장하지 마세요.** 파서 테스트가 통과했다거나 공개 사이트 하나가 열렸다고 해서
"모든 트래픽 보호"나 "통신사 우회 성공"이라고 쓰지 않습니다. 이 프로젝트의 신뢰는 거기서 나옵니다.

시크릿DNS의 코드·바이너리·로고·도메인 목록 등 자산은 호환 라이선스 없이 가져오지 않습니다.
브라우징 기록, 자격 증명, 기기 식별자, 서명 키, 사내 네트워크 정보를 이슈나 아티팩트에 넣지 마세요.

## 커밋 메시지

의도를 담은 한 줄 제목을 쓰고, 본문에 `Tested:` / `Constraint:` / `Rejected:` / `Not-tested:`
트레일러를 필요한 만큼 붙입니다. `Not-tested:`를 솔직하게 쓰는 것이 이 저장소의 방식입니다.

```text
Reject reused process identities before applying proxy settings

kqueue가 PID를 재사용한 다른 프로세스를 따라가면 엉뚱한 종료에 복구가 돌 수 있다.
등록 전후로 프로세스 시작 시각을 비교해 동일 인스턴스임을 확인한다.

Constraint: 기존 복구 기록 형식을 그대로 읽을 수 있어야 한다.

Tested: 17개 Rust 테스트, stale-identity 시나리오 arm64/x86_64 PASS.

Not-tested: 실제 맥에서의 강제 종료 후 재부팅 경로.
```

## 행동 규범

한국어와 영어 모두 환영합니다. 서툰 질문에 면박 주지 않습니다.
처음 기여하는 사람이 막히면 그건 대체로 문서 잘못입니다 — 이슈로 알려주세요.
