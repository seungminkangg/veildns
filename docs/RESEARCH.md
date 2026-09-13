# VeilDNS 설계 근거와 원본 대응

조사 기준일: 2026-09-13. 이 문서는 공식 자료에 근거한 기능 분석과 설계 결정이다. 구현·테스트·서명·실제 통신사 환경에서의 성공을 인증하는 문서가 아니다.

## 분석 대상과 독립 구현

사용자가 지정한 글은 길호넷의 **시크릿DNS 4.0.3 업데이트** 공지다. 본문 히스토리는 4.0.3을 **2026/09/13**, 4.0.2를 **2026/09/04**로 구분한다. 4.0.3의 변화는 시작·자동 실행 개선, 프록시 혼합 개편과 사이트 편집·설정 유지, 사용자 DNS 서버 추가·선택, 일부 통신사의 암호화 DNS 연결 개선, 도메인 주소 및 Cloudflare 연결 주소 추가, DNS 실패 시 서버 변경 안내와 상태 문구 개선이다. 4.0.2의 간헐적 연결 중단·DNS 서버 자동 전환 개선과 혼동하지 않는다. [공식 공지 6269](https://kilho.net/archives/notice/6269)

제품 공식 페이지는 DoH, SNI 문자열 분할, 지정 도메인과 예외 목록, 접속 도메인 확인, 프록시 혼합을 설명한다. 추천 설정은 암호화 DNS와 직접 지정한 도메인의 SNI 분할이다. 원본은 Windows 설정을 변경하지 않는다고 명시하고, 관련 기술로 WinDivert와 DNSCrypt를 연결한다. 이 설명은 원본 Windows 제품에 대한 것이며 macOS 구현에도 자동으로 성립하지 않는다. [시크릿DNS 공식 페이지](https://secretdns.kilho.net/)

공식 페이지에서 확인한 배포 조건은 **Freeware**다. 조사한 공식 페이지에서 원본 소스 저장소나 수정·재라이선스를 허용하는 오픈소스 라이선스는 확인하지 못했다. 따라서 VeilDNS는 공개된 기능 설명과 프로토콜 규격을 참고한 독립 구현으로 만든다. 원본 코드·바이너리·로고·기본 도메인 목록을 복사하거나 재배포하지 않으며, 공식 macOS판이나 길호넷과의 제휴 제품으로 표시하지 않는다. 이 저장소의 라이선스는 VeilDNS 자체 코드에 적용된다. [공식 라이선스 표기](https://secretdns.kilho.net/)

## 선택한 구조

```text
시스템 프록시를 따르는 앱
  → 127.0.0.1의 Rust HTTP / CONNECT 프록시
  → DoH로 목적지 해석
  → 선택한 TLS 연결의 ClientHello record 분할
  → 원래 서버

SwiftUI 앱
  → 엔진 수명·설정 관리
  → macOS 서비스별 프록시 설정 저장·적용·복원

선택 기능: 사용자가 설치하는 DNS mobileconfig
  → macOS 시스템 resolver의 암호화 DNS 설정
```

HTTPS는 클라이언트와 원래 서버 사이의 TLS 연결을 유지한다. 인증서를 설치하거나 HTTPS 본문을 복호화하는 구조가 아니다. 단, 평문 HTTP 자체를 암호화해 주지는 않는다.

| 구성 | 결정과 이유 | 공식 근거 |
| --- | --- | --- |
| 네트워크 엔진 | Rust 안정판 계열. macOS 이외에서도 파서·네트워크 코어를 테스트하고 macOS UI와 분리한다. 조사일 최신 공식 발표는 2026-09-03의 1.98.1이다. | [Rust 출시 목록](https://blog.rust-lang.org/releases/) |
| 비동기 I/O | Tokio의 TCP, 타이머, 작업 취소·동시성 제어를 사용한다. 채택만으로 자원 제한이나 오류 처리가 완성되지는 않는다. | [Tokio 공식 설명](https://tokio.rs/) |
| DoH HTTP 클라이언트 | reqwest와 Rustls 계열 TLS를 사용한다. 클라이언트를 재사용하고 자체 프록시 상속·자동 redirect를 명시적으로 제어한다. | [reqwest 공식 crate 문서](https://docs.rs/reqwest/latest/reqwest/) |
| macOS UI | SwiftUI 네이티브 앱. 조사에서 확인한 안정 Swift 발표는 6.3.3이며 발표문은 Xcode 26.6 포함을 명시한다. 패키지 최소 버전과 실제 빌드에 사용한 버전은 구분한다. | [Swift 6.3.3 발표](https://forums.swift.org/t/announcing-swift-6-3-3/87888) |
| 시스템 통합 | `networksetup`으로 서비스별 웹·보안 웹 프록시를 관리한다. 실제 macOS 상태와 명령 종료 결과를 검증한다. | [Apple networksetup 안내](https://support.apple.com/en-lamr/guide/remote-desktop/apdd0c5a2d5/mac) |

도구 버전은 조사 시점의 스냅샷이다. 실제 고정 버전은 저장소의 toolchain·manifest·lockfile 및 CI 기록이 기준이다. 아직 출시되지 않은 도구를 안정판처럼 표기하지 않는다.

## 원본 기능과 대응 범위

아래 표는 설계 대응표이며 완료 체크리스트가 아니다. 특정 기능의 존재와 통과 여부는 해당 소스와 테스트 결과로 별도 확인한다.

| 원본에서 확인한 기능 | VeilDNS의 대응 | 차이 또는 범위 |
| --- | --- | --- |
| DNS over HTTPS | Rust 프록시가 목적지 도메인을 DoH로 해석 | 기본 보호 대상은 프록시를 통과하는 요청. OS의 모든 DNS 패킷을 가로채지 않음 |
| SNI 문자열 분할 | 지정 도메인의 ClientHello를 SNI 위치에서 여러 TLS record로 분할 | 원본의 Windows 패킷 처리와 동일한 구현이 아님. 같은 통신사 우회 결과를 보장하지 않음 |
| 지정 도메인·예외 목록 | 분할 대상과 예외를 설정으로 구분 | 분할을 생략하는 예외가 곧 프록시·DoH까지 생략한다는 뜻은 아님. 각 설정의 실제 의미를 UI·문서에 명시 |
| 사용자 DNS 서버 | 사용자 DoH endpoint 설정 | HTTPS·응답 검증·bootstrap 동작을 포함해 확인해야 함 |
| Windows 설정 불변 | macOS 프록시 설정의 저장·적용·복원 | 시스템 설정을 변경함. 원본의 설정 불변 특성을 계승했다고 설명하지 않음 |
| 도메인별 외부 프록시 혼합 | 별도 범위 | 로컬 프록시 사용 자체는 원본의 외부 프록시 혼합과 동등하지 않음. 독립 구현·검증 전 지원 기능으로 홍보하지 않음 |
| 접속 도메인 기록·자동 실행 개선 | macOS 앱 수명·상태·진단 기능으로 검토 | 원본의 UI·기록·자동 업데이트 기능 전체와 동일하다고 주장하지 않음 |
| 시스템 DNS 보호 확장 | 선택적 DNS mobileconfig | 사용자가 별도로 설치·활성화해야 하며 SNI 분할을 제공하지 않음 |

## 프로토콜과 복구 원칙

HTTP CONNECT는 목적지 `host:port`로 TCP 터널을 만든다. 성공 응답 이후의 양방향 바이트를 전달하며, 연결 실패를 성공으로 먼저 보고하지 않는다. 프록시 요청의 길이·대기 시간·목적지·동시 연결 수를 제한하고 CONNECT 성공 응답에 `Content-Length`나 `Transfer-Encoding`을 넣지 않는다. [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)

TCP read 한 번을 ClientHello 하나로 취급하지 않는다. TLS record와 handshake 길이를 확인하고 불완전 입력·여러 record·큰 ClientHello를 처리해야 한다. TLS는 handshake가 여러 record에 걸치는 것을 허용하되 다른 record 종류를 그 사이에 끼우지 못하게 한다. 분할 시 handshake payload를 그대로 유지하고 record header와 길이만 일관되게 구성한다. **TLS record 분할과 IP fragmentation, TCP segment 분할은 서로 다르다.** TCP `write`를 나누거나 `TCP_NODELAY`를 켰다는 이유로 실제 패킷 경계를 보장하지 않는다. [RFC 8446 §5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1)

DoH는 DNS wire message를 HTTPS로 전달하는 RFC 8484를 기준으로 한다. 응답 크기·종료 시간·DNS 질문 일치·응답 상태를 검증한다. 자체 macOS 프록시를 DoH 클라이언트가 다시 사용하면 연결 루프가 생길 수 있으므로 프록시 상속을 끈다. reqwest의 기본 자동 redirect도 명시적으로 제한한다. 인증서 검증을 끄거나 DoH 실패를 평문 DNS 재시도로 감추지 않는다. endpoint의 IP bootstrap은 대상 서버의 TLS 신원 검증을 유지해야 한다. [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html), [reqwest proxy·redirect 기본값](https://docs.rs/reqwest/latest/reqwest/)

프록시 설정 적용 전 서비스별 서버·포트·활성화 상태를 복구 자료로 저장한다. 시작 실패·정상 종료·이전 비정상 종료 후 복구 경로가 필요하다. 사용자나 다른 앱이 이후 변경한 설정을 덮어쓰지 않도록 현재 설정이 VeilDNS 소유인지 확인한다. 기존 인증 프록시 비밀번호를 복구할 수 있다고 가정하지 않는다. 관리자 권한이 필요한 경우 macOS 권한 승인 UI를 사용하며 비밀번호를 앱 설정에 저장하지 않는다.

## 보호하지 않는 것

- HTTP/HTTPS 시스템 프록시를 무시하는 앱과 직접 소켓 연결.
- 일반 CONNECT가 전달하지 않는 UDP·QUIC/HTTP/3 트래픽. 브라우저의 TCP fallback은 브라우저·정책별 실측 대상이다.
- DoH 서버 또는 목적지 IP 자체의 차단, 정확히 재조립하는 DPI, 모든 기업 방화벽 규칙.
- VPN식 IP 주소 변경·익명화. DoH 제공자는 질의를 처리하며 목적지 IP 등 다른 네트워크 정보도 남는다.
- ECH 내부의 숨겨진 서버 이름. ClientHello에서 보이는 정보만 처리할 수 있고 ECH를 해독하지 않는다.

따라서 기본 모드를 “Mac 전체 DNS·모든 앱 보호”로 표시하지 않는다. [CONNECT의 TCP 터널 의미](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)

선택적 `com.apple.dnsSettings.managed` profile은 macOS에서 수동 설치가 허용되는 암호화 DNS 구성 경로다. 설치 여부와 시스템 resolver의 실제 사용 여부는 별도 확인해야 하며, 앱 자체 DNS·VPN·기존 네트워크 구성까지 항상 지배한다고 주장하지 않는다. 사내 도메인·captive portal·VPN과의 상호작용도 고려한다. [Apple DNSSettings payload](https://developer.apple.com/documentation/devicemanagement/dnssettings), [Apple 암호화 DNS 설명](https://developer.apple.com/videos/play/wwdc2020/10047/)

## NetworkExtension으로 확장할 때

더 넓은 트래픽 처리가 필요하면 `NETransparentProxyProvider`와 별도의 DNS 설정/provider가 macOS 정식 통합 후보다. transparent proxy는 자신의 network settings에 지정한 DNS 설정을 무시하며, 이름 기반 연결은 기존 DNS 해석을 거친다. 따라서 transparent proxy 하나를 추가하는 것으로 DoH까지 완성되지 않는다. [Apple provider 동작](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)

Developer ID 직접 배포에서는 transparent proxy를 system extension으로 패키징하고, 관련 App ID capability·provisioning profile·`app-proxy-provider-systemextension` entitlement를 준비해야 한다. DNS proxy는 `dns-proxy-systemextension`이다. 시스템 DNS 설정만 구성하는 `NEDNSSettingsManager`는 `dns-settings` capability를 사용하는 별도 선택지이며 provider extension 구현은 필요하지 않다. 활성화·서명·설치 동작은 실제 Mac에서 검증한다. [Apple 배포 표 TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment), [NetworkExtension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension), [DNS settings 구성](https://developer.apple.com/videos/play/wwdc2020/10047/)

PF/`pfctl`을 공개 제품의 기반으로 사용하지 않는다. Apple은 PF를 API로 보지 않으며 사용자·운영체제·다른 제품의 규칙과 충돌할 수 있어 NetworkExtension으로 이동할 것을 명시한다. [Apple TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)

일반 사용자용 Developer ID 배포는 Hardened Runtime, 유효한 서명·타임스탬프, notarization·staple 검증을 준비해야 한다. 소스 공개, CI 산출물, ad hoc 서명 앱, notarized 출시 파일은 서로 다른 배포 상태다. [Apple notarization 안내](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)

## 완료 판단에 필요한 증거

파서·설정 복원 단위 테스트, 로컬 HTTP/CONNECT 및 TLS handshake 통합 테스트, 실제 DoH 검증을 구분해 기록한다. 이후 macOS의 Safari/Chrome, IPv4/IPv6, Wi-Fi 전환, sleep/wake, 기존 프록시/VPN, 실패·종료 후 복원을 실측한다. SNI 분할은 패킷 캡처와 실제 대상 서버의 TLS 성공을 함께 확인한다. 통신사별 우회 성공은 그 환경에서의 별도 결과다. Windows에서 코어가 빌드되거나 GitHub macOS CI가 통과해도 이러한 실기 검증을 대신하지 않는다.

비교 조사한 기존 OSS로는 Go 기반 Apache-2.0 [SpoofDPI](https://github.com/xvzc/spoofdpi)와 MIT [ByeDPI](https://github.com/hufrea/byedpi)가 있다. 로컬 프록시·DoH·TLS 분할 방식이 실용적인 비교 대상임을 확인하는 자료이며, VeilDNS가 해당 코드를 포함하거나 동일한 네트워크 결과를 달성했다는 근거는 아니다.
