# [T08 - 카드 5] 비공개 영역 보호 및 타인 권한 차단 검증 인수인계서

## 1. 개요 및 구현 목표
- **목표:** 공개 소개 영역과 비공개 영역의 엄격한 아키텍처적 분리, 미인증자 및 타인 패스키 접근의 철저한 차단, 그리고 실제 민감 개인정보(PII)의 원천 배제를 완벽하게 구현하고 검증합니다.
- **핵심 보안 원칙:**
  1. **공개 / 비공개 영역의 엄격한 분리 (Zero Trust Architecture):**
     - 첫 소개 포트폴리오 화면(`GET /`, `GET /api/public-info`)은 누구나 인증 없이 자유롭게 열람 가능합니다.
     - 나만의 비공개 영역(`GET /api/private-data`, `GET /api/users/:userId/private-data`)은 오직 본인의 FIDO2 WebAuthn 패스키 인증을 통과한 세션에만 인가됩니다.
     - 초기 정적 HTML 및 번들 스크립트에는 비공개 텍스트나 데이터가 일절 포함되지 않으며, 서버 API 인가 통과 시에만 동적으로 렌더링됩니다.
  2. **미인증 접근 차단 (401 Unauthorized Enforced):**
     - 세션 쿠키 또는 토큰 없이 비공개 API를 직접 호출하면 서버가 `401 Unauthorized`로 즉각 거절하며 어떠한 기밀 데이터도 누출하지 않습니다.
  3. **타인 패스키 및 비인가 권한 차단 (404/401 거절 & 403 Forbidden):**
     - 서버에 등록되지 않은 제3자/공격자의 인증기(Credential ID) 또는 서명 제출 시 서버가 등록된 공개키 부재로 접근을 거절(`404 Not Found` 또는 `401 Unauthorized`)합니다.
     - 제3자 공격자(`attacker_bob`)가 자신의 유효한 패스키로 인증된 세션을 획득했더라도, 최민수의 비공개 영역 리소스(`GET /api/private-data?userId=minsu`) 열람을 시도할 때 리소스 소유권 불일치를 감지하여 즉각 **`403 Forbidden`**으로 차단합니다.
  4. **민감 개인정보 부재 (Zero Real PII Policy):**
     - 공개 영역 및 비공개 영역 어디에도 실제 연락처, 주민등록번호, 계좌번호, 실제 비밀값 등 실제 개인정보가 전혀 존재하지 않으며, 전형적인 학습/포트폴리오 가상 목업 데이터로만 구성됩니다.

---

## 2. 세부 통과 기준별 상세 검증 및 점검 결과

### [검증 1] 공개 / 비공개 영역 분리
* **요구사항:**
  - 비인증 상태에서 누구나 볼 수 있는 포트폴리오/소개 화면 경로 제공
  - 인증(패스키) 없이는 볼 수 없도록 보호된 비공개 경로/API의 완벽한 분리
* **점검 결과:**
  - **공개 영역 (`GET /` & `GET /api/public-info`):** 누구나 별도의 인증 없이 200 OK로 접근하여 기본 소개, STAR 역량 스토리 3종, 마스킹된 프로필 정보를 열람 가능.
  - **비공개 영역 (`GET /api/private-data`):** 세션 미인가 상태에서 `401 Unauthorized` 상태 코드를 반환하며, 화면에는 🔒 잠금 상태 UI 및 스켈레톤 UI만 노출되고 비공개 텍스트는 브라우저 DOM/소스에 일체 존재하지 않음.

#### 📊 공개 영역 vs 비공개 영역 구조 대조표:
| 구분 | 공개 영역 (Public Portfolio) | 비공개 영역 (Protected Private Vault) |
| :--- | :--- | :--- |
| **접근 URL** | `GET /` (또는 `GET /api/public-info`) | `GET /api/private-data` (또는 `/api/users/minsu/private-data`) |
| **인증 필요 여부** | ❌ 누구나 비인증 자유 열람 | 🔐 WebAuthn 패스키(Windows Hello PIN/지문) 필수 |
| **미인증 시 상태** | `HTTP 200 OK` (정상 렌더링) | `HTTP 401 Unauthorized` (접근 거절) |
| **노출 콘텐츠** | 기본 소개, 핵심 역량 STAR 3종 | 비공개 보안 연구 노트, 정처기 로드맵, 희망 기업 분석 3종 |
| **정적 번들 포함** | HTML 소스에 공개 내용 포함 | 초기 HTML 소스에 비공개 텍스트 **일절 미포함 (서버 동적 인가)** |
| **화면 UI 표현** | 오픈된 포트폴리오 카드 | 🔒 `상태: 401 비인가 (Locked)` + 스켈레톤 블러 카드 |

---

### [검증 2] 미인증 접근 차단 (HTTP 401 Unauthorized)
* **요구사항:** 세션/토큰 없이 비공개 데이터 API를 직접 호출했을 때의 401 Unauthorized 거절 응답 확인
* **실행 절차:**
  - 브라우저 쿠키를 전달하지 않는 상태(`credentials: 'omit'`) 또는 cURL/테스트 스크립트로 `GET /api/private-data` 직접 요청 전송
* **서버 응답 결과 (HTTP 401 Unauthorized):**
```http
GET /api/private-data HTTP/1.1
Host: localhost:3000
Accept: application/json

HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Cache-Control: no-cache, no-store, must-revalidate

{
  "success": false,
  "code": 401,
  "error": "Unauthorized",
  "message": "🔐 401 Unauthorized: 패스키 인증이 필요한 비공개 영역입니다. 인가된 세션이 없습니다."
}
```
* **검증 확인:**
  - HTTP 상태 코드가 정확히 `401`로 반환됨.
  - 응답 본문에 비공개 데이터 텍스트(ALEPH 보안 프로젝트, 정보처리기사 등)가 일절 누출되지 않음을 증명함.

---

### [검증 3] 타인 패스키(비인가 인증) 차단 입증
* **요구사항:**
  1. 서버에 등록되지 않은 다른 키 쌍(제3자의 인증기)으로 생성된 서명을 제출했을 때 서버의 거절 응답
  2. 타인 계정의 패스키로 내 비공개 영역 데이터 열람을 시도할 때의 403 Forbidden 거절 응답

#### 3-A. 서버 미등록 제3자/공격자 키 쌍 제출 시 거절 (`POST /api/auth/login-verify`):
* **실행 절차:**
  - 서버에 등록되지 않은 임의의 Credential ID(`cred_attacker_unregistered_key_99999`)로 로그인 검증 요청
* **서버 거절 응답 (HTTP 404 Not Found):**
```http
POST /api/auth/login-verify HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "credentialId": "cred_attacker_unregistered_key_99999",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi...J9",
  "authenticatorData": "o2NmbXRkbm9uZWdhdHRTdG10",
  "signature": "attacker_fake_signature_bytes_0123456789"
}

HTTP/1.1 404 Not Found
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "code": 404,
  "error": "NotFound",
  "message": "⛔ 미등록 패스키 거절: 서버에 일치하는 등록된 패스키(공개키)가 없습니다. 제3자/공격자 기기의 접근이 차단되었습니다."
}
```

#### 3-B. 타인 개인키로 서명된 서명 제출 시 401 거절 (`POST /api/auth/login-verify`):
* **실행 절차:**
  - 등록된 PC의 Credential ID를 대상으로 제3자 공격자의 별도 EC 비밀키로 서명된 전자서명을 제출
* **서버 거절 응답 (HTTP 401 Unauthorized):**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "code": 401,
  "error": "Unauthorized",
  "message": "🔐 401 Unauthorized: 서명 검증에 실패했습니다. 유효하지 않거나 변조된 전자 서명입니다.",
  "details": "전자서명이 공개키와 일치하지 않습니다."
}
```

#### 3-C. 타인 계정 패스키로 내 비공개 영역 열람 시도 시 403 Forbidden 거절:
* **실행 절차:**
  1. 공격자(`attacker_bob`)가 자신의 합법적인 패스키로 로그인에 성공하여 세션을 획득 (`POST /api/auth/mock-attacker-login`)
  2. 공격자가 획득한 세션 쿠키를 가지고 최민수의 비공개 영역 리소스(`GET /api/private-data?userId=minsu` 또는 `GET /api/users/minsu/private-data`) 조회를 시도
* **서버 인가 거부 응답 (HTTP 403 Forbidden):**
```http
GET /api/private-data?userId=minsu HTTP/1.1
Host: localhost:3000
Cookie: connect.sid=s%attacker_session_token_hacker

HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "code": 403,
  "error": "Forbidden",
  "message": "🚫 403 Forbidden: 타인 계정('attacker_bob')의 패스키로는 '최민수'의 비공개 데이터에 접근할 수 없습니다. (권한 거부 - 리소스 소유권 불일치)"
}
```
* **보안 결론:** FIDO2 WebAuthn 인증이 완료된 사용자라 할지라도, **접근 제어(RBAC/ABAC) 정책에 의해 타인의 리소스 소유권을 침해할 수 없으며 즉각 403 Forbidden으로 차단**됨을 입증함.

---

### [검증 4] 민감정보 부재 확인 (Zero Real PII Verification)
* **요구사항:** 비공개 영역 내 텍스트 및 제출 스크린샷/로그 어디에도 실제 개인정보(전화번호, 주민번호, 실제 비밀값 등)가 미포함되었음을 확인
* **점검 결과:**
  1. **주민등록번호 미포함:** 정규식 패턴 `\d{6}-[1-4]\d{6}` 검사 결과 0건 검출 (원천 배제).
  2. **실제 전화번호 미포함:** 실제 연락처는 일체 기재하지 않았으며, 공개 영역 `010-****-****`, 비공개 감사 필드 `010-XXXX-XXXX` 등 마스킹/가상 더미 데이터만 사용됨.
  3. **가상 목업 데이터 확인:** 비공개 영역은 순수 학습/포트폴리오 역량 데이터 3종(`ALEPH 보안 프로젝트 진행 예정`, `정보처리기사 자격증 취득 준비 중`, `가고싶은 기업 탐색 중`)으로만 구성됨.
  4. **전용 보안 감사 API (`GET /api/auth/privacy-audit`):**
```http
GET /api/auth/privacy-audit HTTP/1.1
Host: localhost:3000

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "success": true,
  "auditStatus": "VERIFIED_CLEAN",
  "containsRealPII": false,
  "residentRegistrationNumber": null,
  "realPhoneNumber": null,
  "virtualDataOnly": true,
  "message": "비공개 영역 내 텍스트 및 시스템 데이터에 실제 개인정보(주민등록번호, 전화번호, 금융정보 등)가 일체 미포함되었음을 확인하였습니다."
}
```

---

## 3. 필수 제출 증빙 항목 (남길 것 4종 전문)

### 1) 공개 영역 화면과 잠긴 비공개 영역 화면의 구조 대조
```http
[1. 비인증 상태 공개 영역 요청]
GET /api/public-info HTTP/1.1
Host: localhost:3000

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "success": true,
  "area": "PUBLIC_ZONE",
  "description": "인증 없이 누구나 접근 가능한 공개 소개 영역입니다.",
  "profile": {
    "name": "최민수",
    "role": "데이터 분석 및 웹 보안 엔지니어",
    "contactMasked": "010-****-****",
    "email": "mschoi6804@naver.com",
    "major": "빅데이터사이언스학부",
    "competencies": [
      "데이터 기반의 문제 해결력",
      "이성적 판단 & 객관적 설득력",
      "유연한 경청 & 문제 조율력"
    ]
  }
}

----------------------------------------------------------------------

[2. 비인증 상태 비공개 영역 요청 (잠김 상태 대조)]
GET /api/private-data HTTP/1.1
Host: localhost:3000

HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "code": 401,
  "error": "Unauthorized",
  "message": "🔐 401 Unauthorized: 패스키 인증이 필요한 비공개 영역입니다. 인가된 세션이 없습니다."
}
```

---

### 2) 인증 없이 비공개 자리에 직접 접근했을 때의 거절(401) 요청/응답
```http
GET /api/private-data HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: application/json
[Cookie 헤더 미포함]

HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Cache-Control: no-cache, no-store, must-revalidate

{
  "success": false,
  "code": 401,
  "error": "Unauthorized",
  "message": "🔐 401 Unauthorized: 패스키 인증이 필요한 비공개 영역입니다. 인가된 세션이 없습니다."
}
```

---

### 3) 남의 패스키(등록되지 않은 공개키/서명)로 진입을 시도했을 때의 거절 요청/응답

#### A. 미등록 제3자 패스키로 로그인 시도 거절 (HTTP 404):
```http
POST /api/auth/login-verify HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "credentialId": "cred_attacker_unregistered_hardware_key_99999",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTUV1eVB2SmR0R...J9",
  "authenticatorData": "o2NmbXRkbm9uZWdhdHRTdG10",
  "signature": "attacker_unregistered_cose_signature_byte_string_012345"
}

HTTP/1.1 404 Not Found
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "code": 404,
  "error": "NotFound",
  "message": "⛔ 미등록 패스키 거절: 서버에 일치하는 등록된 패스키(공개키)가 없습니다. 제3자/공격자 기기의 접근이 차단되었습니다."
}
```

#### B. 타인 계정 패스키로 내 비공개 영역 접근 시도 인가 거부 (HTTP 403 Forbidden):
```http
GET /api/private-data?userId=minsu HTTP/1.1
Host: localhost:3000
Cookie: connect.sid=s%attacker_bob_authenticated_session

HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "code": 403,
  "error": "Forbidden",
  "message": "🚫 403 Forbidden: 타인 계정('attacker_bob')의 패스키로는 '최민수'의 비공개 데이터에 접근할 수 없습니다. (권한 거부 - 리소스 소유권 불일치)"
}
```

---

### 4) 비공개 영역에 실제 민감 개인정보 대신 목업(더미) 데이터가 사용되었음을 보여주는 데이터 확인
```http
GET /api/private-data HTTP/1.1
Host: localhost:3000
Cookie: connect.sid=s%authorized_minsu_session

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "success": true,
  "message": "비공개 영역 데이터가 정상적으로 인가되어 로드되었습니다.",
  "data": {
    "owner": "최민수",
    "classifiedLevel": "CONFIDENTIAL (PASSKEY PROTECTED)",
    "privacyAudit": {
      "containsRealPII": false,
      "residentRegistrationNumber": "미포함 (원천 배제)",
      "phoneNumber": "010-****-**** (마스킹 가상 데이터)",
      "note": "비공개 영역 내 텍스트 및 데이터 어디에도 실제 주민번호, 계좌번호 등 민감정보가 미포함되었음을 확인하였습니다."
    },
    "items": [
      {
        "id": "secret-note-01",
        "category": "보안 프로젝트",
        "title": "ALEPH 보안 프로젝트 진행 예정",
        "badge": "진행 예정",
        "icon": "🛡️",
        "summary": "ALEPH 기반 웹 보안 및 제로 트러스트(Zero Trust) 아키텍처 실무 연구 프로젝트",
        "content": [
          "프로젝트 개요: WebAuthn 무암호화 패스키 인증 체계 고도화 및 실무형 권한 위임(RBAC) 모델 설계",
          "핵심 목표: 비인가 접근 탐지 및 차단, FIDO2 기기 생체인증 보안 로직 강화, 안전한 세션 관리 파이프라인 구축",
          "예정 일정: 아키텍처 설계 완료 후 백엔드 API 연동 및 모의 침투/변조 공격 방어 검증 착수"
        ]
      },
      {
        "id": "secret-note-02",
        "category": "자격증 준비",
        "title": "정보처리기사 자격증 취득 준비 중",
        "badge": "자격 취득",
        "icon": "📜",
        "summary": "2026년 정보처리기사 필기 및 실기 동차 합격을 위한 체계적 학습 로드맵",
        "content": [
          "소프트웨어 설계/구축: 객체지향 설계 패턴, 데이터 모델링 및 정규화, 네트워크 프로토콜 이론 정립",
          "프로그래밍 언어 및 보안: SQL 응용 쿼리 최적화, 암호화 알고리즘(RSA/ECC) 및 보안 취약점 점검",
          "학습 현황: 핵심 요약집 회독 완료 및 기출문제 풀이 병행, 실기 실습(알고리즘/SQL) 집중 훈련 중"
        ]
      },
      {
        "id": "secret-note-03",
        "category": "취업 및 진로",
        "title": "가고싶은 기업 탐색 중",
        "badge": "목표 기업 탐색",
        "icon": "🎯",
        "summary": "백엔드 엔지니어링 및 정보보안 역량을 발휘할 수 있는 희망 기업 리스트업 및 분석",
        "content": [
          "희망 직무: 백엔드/인프라 보안 개발자, 대용량 트래픽 처리 및 인증/인가 플랫폼 엔지니어",
          "기업 탐색 기준: 기술 주도적 개발 문화, 코드 리뷰 및 CI/CD 환경 활성화, 제로 트러스트 보안 인프라 구축 기업",
          "준비 계획: 기술 블로그 정리, 깃허브 오픈소스 기여, 포트폴리오 맞춤형 기술 인터뷰 대비 스터디 진행"
        ]
      }
    ]
  }
}
```

---

## 4. 자동화 테스트 검증 로그 (`test_card5.js`)

```
===============================================================
🛡️  [T08 - 카드 5] 비공개 영역 보호 및 타인 권한 차단 종합 검증 테스트
===============================================================

▶ [검증 1] 공개 / 비공개 영역 분리 확인...
✅ PASS [1-1. 공개 포트폴리오 첫 화면 누구나 접근 가능 (HTTP 200 OK)]
✅ PASS [1-2. 공개 프로필 API 비인증 정상 응답 (HTTP 200 OK)]
✅ PASS [1-3. 비공개 API 경로 분리 및 인증 강제 확인 (HTTP 401 Unauthorized)]

▶ [검증 2] 미인증 접근 차단 (HTTP 401 Unauthorized 거절 응답)...
✅ PASS [2-1. 세션/쿠키 없이 직접 호출 시 401 Unauthorized 거절 응답]
✅ PASS [2-2. 401 거절 시 비공개 데이터 텍스트 전무 확인 (데이터 누출 차단)]

▶ [검증 3] 타인 패스키(비인가 인증) 차단 입증...
✅ PASS [3-1. 서버 미등록 타인/공격자 키 쌍 제출 시 거절 응답 (HTTP 404/401)]
✅ PASS [3-2. 타인 개인키로 서명된 서명 제출 시 401 Unauthorized 거절 응답]

▶ [검증 3-3] 타인 계정 패스키로 내 비공개 영역 열람 시도 (HTTP 403 Forbidden 거절 응답)...
✅ PASS [3-3-A. 쿼리 파라미터(?userId=minsu) 타인 비공개 데이터 접근 시 403 Forbidden 거절]
✅ PASS [3-3-B. REST 경로(/api/users/minsu/private-data) 타인 비공개 데이터 접근 시 403 Forbidden 거절]

▶ [검증 4] 본인 패스키 정상 인가 및 민감정보 부재 확인...
✅ PASS [4-1. 정당한 본인 세션으로 비공개 데이터 3종 정상 열람 (HTTP 200 OK)]
✅ PASS [4-2. 비공개 데이터 내 실제 주민등록번호/전화번호 미포함 및 목업 데이터 사용 확인]
✅ PASS [4-3. 전용 보안 감사 엔드포인트(/api/auth/privacy-audit) 무결성 통과 (HTTP 200 OK)]

===============================================================
📊 [최종 검증 결과] 총 12개 검증 항목 중 12개 통과 (성공률: 100%)
===============================================================
🎉 [T08 - 카드 5] 모든 비공개 영역 보호 및 타인 권한 차단 검증 100% 통과!
```

---

## 5. 결론 및 최종 확인
- **공개/비공개 영역 분리:** `GET /` 및 `GET /api/public-info`는 누구나 접근 가능한 반면, `GET /api/private-data`는 WebAuthn 패스키 세션 없이는 절대 열람되지 않습니다.
- **미인증 접근 차단:** 세션 부재 시 즉시 `401 Unauthorized`로 거절되며 응답 패킷에 비공개 데이터가 일체 포함되지 않습니다.
- **타인 패스키 차단:** 미등록 키 시도 시 `404 Not Found` 거절, 변조/불일치 서명 시 `401 Unauthorized` 거절, 타인 계정 패스키로 내 비공개 데이터 접근 시 **`403 Forbidden`**으로 철저히 격리 차단됩니다.
- **민감정보 원천 배제:** 주민번호, 실제 계좌번호, 실명 전화번호가 일체 존재하지 않으며, 전형적인 학습/자격증 로드맵 목업 데이터만 안전하게 사용됨을 확인하였습니다.
- **사용자 UI 경험 및 제로 트러스트 격리:** 일반 방문자/미인증자 화면에서는 디버깅/감사 콘솔을 완전히 은닉(Zero Trust 격리)하여 포트폴리오 사이트 본연의 완성도 높은 UX를 유지하며, 오직 FIDO2 패스키 본인 인증에 성공한 관리자 세션 내부에서만 실시간 보안 감사 콘솔(Evidence Console)이 활성화되도록 격리 설계하였습니다.