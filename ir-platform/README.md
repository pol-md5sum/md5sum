# irsys — 침해사고 대응·분석 종합시스템

「침해사고 대응·분석 종합시스템 고도화 기획안」의 1단계 핵심 기능과 2·3단계 일부를 구현한 명령행 시스템입니다.
Python 3.10 이상 표준 라이브러리만으로 동작하므로, 인터넷이 차단된 분석 구역에서도 그대로 실행할 수 있습니다.

## 구현 현황

| 모듈 | 기획안 단계 | 상태 | 구현 내용 |
|---|---|---|---|
| M1 사건 관리 | 1단계 | ✅ | 사건 번호 발급, 심각도(자산 중요도×위협도), 단계 전환 규칙, 활동 기록 |
| M2 증거 수집·보존 | 1단계 | ✅ | MD5·SHA-256 이중 해시, 읽기 전용 보관, 해시 체인 취급 이력, 열람 전 재검증, 반출 기록 |
| M7 이메일 분석 | 1단계 | ✅ | 제목·일시(UTC/KST)·수발신 계정·경유지·최초 발신 IP·SPF/DKIM/DMARC·사칭 징후·첨부·링크 (.eml) |
| M8 IOC·OSINT | 1단계 | ✅ | IOC 추출·정규화·무력화, VirusTotal·Criminal IP·Shodan 조회, 캐시, 호출 간격 제한 |
| M12 보고서 | 1단계 | ✅ | Markdown 보고서, 보고서용 문장, 3줄 요약, 개인정보 자동 마스킹 |
| 법적 요건 | 1단계 | ✅ | 신고 기한 계산(규칙 파일), 개인정보 마스킹 |
| M3 타임라인 | 2단계 | 🟡 일부 | CSV·JSONL(Hayabusa·Plaso 열 매핑) 가져오기 + 내부 기록 통합. 원본 로그 직접 파싱은 미구현 |
| M5 정적 분석 | 2단계 | ✅ | 형식 판별, PE 헤더·섹션 엔트로피·가져오기·imphash·PDB, 문자열·한글 흔적, PowerShell 인코딩 해제, 스크립트·웹쉘 규칙, YARA(선택) |
| M9 APT 연계 | 3단계 | ✅ | 6개 증거 축 가중 점수, 위장 대비 규칙, Kimsuky·Lazarus·APT37·Andariel 초기 프로필 |
| M4 메모리 분석 | 2단계 | ⬜ | Volatility 3 연동 필요 |
| M6 동적 분석 | 3단계 | ⬜ | 격리 샌드박스(CAPEv2) 인프라 필요 |
| M10 네트워크·로그 | 2단계 | ⬜ | Zeek·Suricata 연동 필요 |
| M11 대응 자동화 | 4단계 | ⬜ | EDR·방화벽 API와 승인 절차 필요 |
| .msg/.pst/.ost | 1단계 | ⬜ | libpff 등 외부 파서 필요 |

## 설치와 실행

```bash
cd ir-platform
python3 -m irsys --help          # 설치 없이 실행
pip install -e '.[test]'         # 또는 설치 후 irsys 명령 사용
python3 -m pytest                # 테스트
```

데이터(SQLite DB와 증거 보관소)는 `IRSYS_HOME`(기본 `./irsys-data`)에 저장됩니다. 저장소에는 올리지 마십시오.

## 사용 예

```bash
export IRSYS_HOME=/secure/irsys IRSYS_ACTOR=홍분석관

# 1) 사건 접수 (유형: intrusion, pii_leak, malware, phishing, other)
irsys case new --title "자문 요청 사칭 피싱" --category phishing --asset 4 --threat 4

# 2) 메일 분석: 파일을 주면 먼저 증거로 등록(해시 고정)한 뒤 보관 사본을 분석
irsys email IR-2026-0001 suspicious.eml

# 3) 첨부파일·의심 파일 정적 분석 (실행하지 않음)
irsys static IR-2026-0001 attachment.lnk --yara rules/apt.yar

# 4) IOC 평판 조회
export IRSYS_VT_KEY=... IRSYS_CRIMINALIP_KEY=... IRSYS_SHODAN_KEY=...
irsys ioc enrich IR-2026-0001 --services vt,criminalip,shodan

# 5) 타임라인, APT 연계, 보고서
irsys timeline import IR-2026-0001 hayabusa.csv --label Hayabusa
irsys timeline build IR-2026-0001
irsys apt IR-2026-0001 --text "대북정책 세미나"
irsys report IR-2026-0001 --out IR-2026-0001.md

# 증거 무결성과 취급 이력
irsys evidence verify IR-2026-0001-EV001
irsys evidence custody IR-2026-0001-EV001
irsys evidence export IR-2026-0001-EV001 ./out --reason "수사기관 제출"
```

## 환경 변수

| 변수 | 용도 |
|---|---|
| `IRSYS_HOME` | DB·증거 보관 경로 |
| `IRSYS_ACTOR` | 작업자 이름(이력에 기록) |
| `IRSYS_VT_KEY`, `IRSYS_CRIMINALIP_KEY`, `IRSYS_SHODAN_KEY` | OSINT API 키. 코드·저장소에 쓰지 말고 비밀 저장소에서 주입 |
| `IRSYS_VT_INTERVAL` 등 `IRSYS_<서비스>_INTERVAL` | 호출 간격(초). VirusTotal 무료 API 기본 15초 |
| `IRSYS_CA_BUNDLE` | 사내 프록시를 거칠 때 신뢰할 CA 묶음 |

## 설계 원칙

- **증거 무결성**: 수집 즉시 해시를 고정하고, 분석·반출 전에 매번 다시 검증합니다. 취급 이력은 앞 항목의 해시를 포함하는 체인이어서 DB를 고치면 `evidence custody`가 탐지합니다.
- **샘플 비실행**: 보관 파일에는 `.evidence` 확장자를 붙이고 읽기 전용으로 둡니다. 정적 분석은 바이트만 읽습니다.
- **외부 노출 최소화**: OSINT 조회는 해시·IP·도메인·URL만 보내며 파일을 업로드하지 않습니다. 피해자 측 주소·도메인과 Message-ID는 IOC에서 제외합니다.
- **개인정보 보호**: 보고서의 주민등록번호·휴대전화·카드번호·피해자 이메일을 자동 마스킹합니다(공격자 주소는 IOC로 유지).
- **귀속은 추정**: APT 점수는 신뢰도 등급으로만 표현합니다. 인프라·TTP 근거 없이 코드·언어 흔적만으로는 '높음'을 주지 않습니다.

## 운영 전 확인 사항

1. `irsys/data/legal_rules.json`의 신고 기한·조문을 국가법령정보센터 최신 조문으로 확인하고 `verified`를 `true`로 바꿉니다.
2. `irsys/data/apt_profiles.json`의 기법·악성코드 목록을 MITRE ATT&CK 원문과 대조하고, 출처가 확인된 IOC·imphash만 추가합니다.
3. 무료 OSINT API는 상업적 사용이 제한될 수 있으므로 각 서비스 약관을 확인합니다.
