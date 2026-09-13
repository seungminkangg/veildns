# 선택 기능: macOS 시스템 DNS 프로파일

VeilDNS의 로컬 프록시와 별개로 macOS 시스템 resolver에 DNS over HTTPS를 설정하려는 사용자를 위한 파일이다. **설치는 선택이며, VeilDNS 앱을 중지·종료·삭제해도 설치된 프로파일은 유지된다.** 해제할 때는 시스템 설정에서 프로파일을 직접 제거한다.

| 프로파일 | DNS 제공자와 HTTPS endpoint | bootstrap 주소 |
| --- | --- | --- |
| [VeilDNS-Cloudflare.mobileconfig](../profiles/VeilDNS-Cloudflare.mobileconfig) | Cloudflare · `https://cloudflare-dns.com/dns-query` | `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001` |
| [VeilDNS-Google.mobileconfig](../profiles/VeilDNS-Google.mobileconfig) | Google · `https://dns.google/dns-query` | `8.8.8.8`, `8.8.4.4`, `2001:4860:4860::8888`, `2001:4860:4860::8844` |

주소와 endpoint는 제공자 공식 문서에서 확인했다. 두 파일 중 **하나만** 설치한다. 제공자를 바꿀 때는 이전 VeilDNS DNS 프로파일을 제거한 다음 새 파일을 설치한다. 프로파일 표시명은 `VeilDNS - Cloudflare DNS over HTTPS` 또는 `VeilDNS - Google DNS over HTTPS`다. [Cloudflare endpoint와 주소](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/), [Google endpoint](https://developers.google.com/speed/public-dns/docs/doh), [Google 주소](https://developers.google.com/speed/public-dns/docs/using)

## 무엇을 설정하는가

각 XML plist에는 `com.apple.dnsSettings.managed` payload 하나만 있다. `DNSProtocol`은 `HTTPS`, `ServerURL`은 위 주소이며, IPv4·IPv6 `ServerAddresses`를 함께 제공한다. macOS는 URL의 호스트로 서버 인증서를 검증한다. `SupplementalMatchDomains`를 생략해 시스템 resolver의 모든 도메인을 대상으로 하고, 제한 조건 없는 `OnDemandRules`의 `Connect`를 사용한다. [Apple DNS payload 스키마](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.dnsSettings.managed.yaml)

이 기능은 DNS 설정이다. 인증서·VPN·프록시·MDM 등록 payload, 원격 관리 서버, 제거용 비밀번호가 없다. `PayloadRemovalDisallowed=false`이며 비활성화를 금지하지 않는다. 프로파일의 이름에 있는 `managed`는 Apple payload 식별자이며 이 파일을 설치한다고 기기 관리 서비스에 등록되지는 않는다. 두 파일은 서명되지 않은 공개 XML이므로 설치 화면에 미서명으로 표시될 수 있다. [Apple 최상위 profile 스키마](https://github.com/apple/device-management/blob/release/mdm/profiles/TopLevel.yaml)

Apple 스키마상 DNS payload는 macOS 11부터 수동 설치를 지원한다. 이 파일은 OS 26에서 추가된 평문 시스템 DNS failover 허용 옵션을 켜지 않는다. 다만 프로파일의 의도와 특정 OS·VPN·앱 조합에서 실제 사용한 resolver는 구분해서 확인해야 한다.

## 설치

1. 현재 설치된 DNS·VPN 프로파일이 있는지 확인한다. 회사·학교의 내부 DNS가 필요한 환경에서는 기존 구성을 먼저 확인한다.
2. 선택한 `.mobileconfig` 파일을 Finder에서 연다. 파일을 여는 것만으로 설치가 완료되지는 않는다.
3. 최근 macOS에서는 **시스템 설정 → 일반 → 기기 관리(Device Management)**에서 다운로드된 프로파일을 연다. 이전 버전은 시스템 환경설정의 **프로파일** 항목을 사용한다.
4. 제공자, DoH URL, DNS 설정 하나만 포함되어 있는지 내용을 확인하고 설치한다. macOS가 요구하는 관리자 승인은 시스템 UI에서 처리한다.
5. 설치 목록에 표시되는지 확인하고 아래 검증 절차를 수행한다.

메뉴 위치는 macOS 버전에 따라 달라질 수 있다. 프로파일의 수동 설치·보기·제거 절차는 [Apple 설치 안내](https://support.apple.com/guide/mac-help/use-configuration-profiles-to-standardize-settings-mh35561/mac)를 따른다.

## 제거와 복구

**시스템 설정 → 일반 → 기기 관리**에서 설치한 VeilDNS DNS 프로파일을 선택하고 제거한다. 필요하면 관리자 승인을 진행한다. 제거하면 이 프로파일의 DNS 설정이 해제되고, 남아 있는 네트워크·VPN·다른 프로파일 설정이 다시 적용된다. 원래 Wi-Fi 설정의 값을 강제로 덮어쓰는 제거 스크립트는 사용하지 않는다. [Apple 프로파일 관리 안내](https://support.apple.com/guide/mac-help/change-device-management-settings-mh35474/mac)

인터넷이나 사내 도메인 접속 문제가 생긴 경우 VeilDNS 앱의 중지 버튼만 눌러서는 이 프로파일이 제거되지 않는다. 프로파일을 제거하고 앱·브라우저를 다시 연 뒤 접속을 확인한다. 이 파일의 삭제나 앱 삭제도 설치된 프로파일을 제거하지 않는다.

## 프록시 기능과 실제 보호 범위

| 연결 경로 | 적용되는 DNS |
| --- | --- |
| VeilDNS 로컬 프록시가 직접 해석하는 도메인 | Rust 엔진에 설정한 DoH 제공자. 이 프로파일 선택과 별개 |
| macOS 시스템 resolver를 사용하는 앱 | OS가 활성화한 이 DNS 프로파일의 적용 대상 |
| VPN 내부 DNS·사내 split DNS | VPN과 OS 정책이 우선하거나 별도 범위를 처리할 수 있음 |
| 브라우저·앱 자체의 DoH 또는 DNS 구현 | 앱 설정에 따라 이 프로파일을 사용하지 않을 수 있음 |

Apple은 VPN 내부 해석에서 VPN DNS가 사용되며, captive portal과 사내 도메인 예외를 고려해야 한다고 설명한다. 별도 DNS profile·NetworkExtension과의 중복 우선순위를 이 프로젝트가 제어하지는 않는다. 따라서 “프로파일 설치됨”을 “모든 앱의 DNS가 암호화됨”과 같게 표시하지 않는다. [Apple encrypted DNS 설명](https://developer.apple.com/videos/play/wwdc2020/10047/)

이 프로파일은 SNI 분할·IP 변경·익명화·전체 트래픽 VPN을 제공하지 않는다. DoH 제공자는 전송된 DNS 질의를 처리한다. 모든 도메인을 대상으로 하므로 공용 DNS가 모르는 사내 이름은 실패할 수 있다. 그런 경우 profile 제거 또는 관리자가 확인한 도메인 예외 구성이 필요하다.

## 검증 상태와 재현

이 저장소의 파일은 Python 표준 라이브러리 `plistlib`로 파싱·재직렬화하고, 단일 DNS payload, HTTPS endpoint, IPv4/IPv6 주소, 전체 도메인 규칙, 제거 허용, 고유 UUID·identifier를 확인한다. 루트 디렉터리에서 실행한다.

```sh
python3 profiles/validate_profiles.py
```

macOS에서는 추가로 XML 구문을 확인할 수 있다.

```sh
plutil -lint profiles/VeilDNS-Cloudflare.mobileconfig
plutil -lint profiles/VeilDNS-Google.mobileconfig
```

**정적 검증은 설치·네트워크 동작 증거가 아니다.** 실제 Mac에서 한 파일의 설치, 시스템 resolver를 사용하는 앱의 새 도메인 해석, OS 네트워크 진단 또는 패킷 캡처, VPN·Wi-Fi 전환, 앱 종료 후 유지, 프로파일 제거 후 복원을 확인해야 한다. `dig @1.1.1.1`처럼 resolver를 직접 지정한 명령이나 브라우저의 자체 Secure DNS 결과만으로 OS 프로파일의 동작을 입증할 수 없다. `scutil --dns`의 설정 목록만으로 암호화 전송 성공을 단정하지 않는다.
