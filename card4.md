# [T08 - 카드 4] 다중 패스키 등록 및 삭제(분실 대비) 구현 및 검증 인수인계서

## 1. 개요 및 구현 목표
- **목표:** 기기 분실·교체 또는 다중 디바이스 사용 환경에 대비하여 **복수(2개 이상)의 패스키 등록**, **단일 패스키 삭제(해지)**, **삭제 후 남은 패스키의 로그인 지속성**, 그리고 **삭제된 패스키의 접근 차단**을 완벽하게 구현하고 검증합니다.
- **핵심 보안 원칙:**
  1. **다중 기기 자율 등록 (Multi-Authenticator Support):** 사용자는 주 기기(Windows Hello PC) 외에도 보조 기기(스마트폰 FaceID, Mac Touch ID, 하드웨어 보안키 등)를 복수로 등록할 수 있어야 합니다.
  2. **독립적 암호 키페어 관리:** 각 기기는 독립적인 ECDSA P-256 비대칭 키페어를 생성하며, 서버는 각각의 Credential ID와 Public Key를 개별 레코드로 관리합니다.
  3. **무중단 인증 연속성 (High Availability):** 하나의 패스키를 분실하여 삭제하더라도, 등록되어 있던 다른 보조 패스키로 로그인 및 비공개 영역 접근이 중단 없이 가능해야 합니다.
  4. **즉각적 해지 반영 (Instant Cryptographic Revocation):** 삭제 처리된 패스키의 Credential ID는 서버 저장소에서 완전히 파기되어, 해당 기기로 어떠한 인증이나 비공개 데이터 조회가 불가능해야 합니다.

---

## 2. 세부 통과 기준별 상세 검증

### [검증 1] 다중 패스키 등록 지원
* **요구사항:** 단일 사용자 계정에 2개 이상의 패스키 크리덴셜(Credential ID & Public Key)이 저장소에 등록되고, 화면 목록에 각각의 고유 별칭으로 노출되어야 한다.
* **구현 엔드포인트:** `POST /api/auth/register-verify` 및 `GET /api/auth/passkeys`
* **검증 결과:**
  - 주 기기(Windows PC) 및 보조 기기(iPhone FaceID) 2개의 서로 다른 키페어가 등록 완료됨 (HTTP 201)
  - `GET /api/auth/passkeys` 조회 시 총 2개 이상의 고유 레코드가 반환됨 (HTTP 200 OK)

#### 서버에 저장된 다중 패스키 목록 전문 (`GET /api/auth/passkeys`):
```json
{
  "success": true,
  "count": 2,
  "passkeys": [
    {
      "id": "cred_card4_primary_win_1791195586877",
      "name": "주 기기: 내 윈도우 PC (Windows Hello)",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXyNX/eKSm0O9KdUYJ5YadwJaFkMx\niLzG5RH3vRxkMHpVCFi/VPqYmyTzcBzrT4dJLVLyTJ9K5DNlp7Uk1ZQUmA==\n-----END PUBLIC KEY-----",
      "publicKeyType": "ECC P-256 (ES256 ECDSA Public Key)",
      "isPassword": false,
      "authenticatorType": "기기 자체 보안 영역 (Windows Hello / TPM)",
      "registeredAt": "2026-10-05T00:00:00.000Z"
    },
    {
      "id": "cred_card4_backup_iphone_1791195586887",
      "name": "보조 기기: 내 아이폰 (FaceID / iCloud 키체인)",
      "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi6CATQ++gCY89OSSZD7Z5wdigx7+\nIQD4bO79KHzc3erF5J/fY/WBnYWVqGYIwbl0rl+yquKAQAl1UvMU5Bbemg==\n-----END PUBLIC KEY-----",
      "publicKeyType": "ECC P-256 (ES256 ECDSA Public Key)",
      "isPassword": false,
      "authenticatorType": "외부/모바일 플랫폼 인증기 (FaceID / iCloud 키체인)",
      "registeredAt": "2026-10-05T00:00:00.000Z"
    }
  ]
}
```

---

### [검증 2] 패스키 1개 삭제 기능 및 저장소 제거 검증
* **요구사항:** 등록된 패스키 중 1개를 명시적으로 삭제(해지) 요청하고, 서버 저장소에서 해당 패스키 레코드가 정상 제거되었음을 입증한다.
* **구현 엔드포인트:** `DELETE /api/auth/passkeys/:id`
* **실행 절차:**
  - 1번 주 기기(`cred_card4_primary_win_1791195586877`)에 대해 삭제 요청 전송
* **서버 처리 응답 (HTTP 200 OK):**
```json
{
  "success": true,
  "message": "패스키 \"주 기기: 내 윈도우 PC (Windows Hello)\"이(가) 정상적으로 삭제되었습니다.",
  "remainingCount": 1
}
```
* **삭제 후 저장소 재조회 결과:**
  - `cred_card4_primary_win_1791195586877`: **완전 제거 확인 (0건)**
  - `cred_card4_backup_iphone_1791195586887`: **정상 보존 확인 (1건 유지)**

---

### [검증 3] 남은 보조 패스키로 정상 로그인 지속성 검증
* **요구사항:** 1번 패스키를 삭제한 후에도 남아 있는 2번 보조 패스키로 정상 로그인되어 비공개 영역에 접근 가능해야 한다.
* **실행 절차:**
  1. `POST /api/auth/login-options` 호출 ➔ 서버가 반환하는 `allowCredentials` 목록 확인:
     - 포함: `cred_card4_backup_iphone_1791195586887` (남은 패스키)
     - 제외: `cred_card4_primary_win_1791195586877` (삭제된 패스키)
  2. 2번 보조 패스키의 개인키로 유효한 서명을 생성하여 `POST /api/auth/login-verify` 전송
* **서버 검증 결과 (HTTP 200 OK):**
```json
{
  "success": true,
  "message": "🎉 [보조 기기: 내 아이폰 (FaceID / iCloud 키체인)] 패스키(Windows Hello PIN / 지문)로 성공적으로 로그인되었습니다!",
  "user": "최민수",
  "passkey": {
    "id": "cred_card4_backup_iphone_1791195586887",
    "name": "보조 기기: 내 아이폰 (FaceID / iCloud 키체인)",
    "authenticatorType": "외부/모바일 플랫폼 인증기 (FaceID / iCloud 키체인)"
  }
}
```
* **비공개 데이터 인가 검증 (`GET /api/private-data`):**
  - 발급된 세션 쿠키로 비공개 데이터 조회 시 **HTTP 200 OK** 반환
  - 3대 비공개 항목(보안 프로젝트, 정처기, 기업 탐색) 정상 열람 확인 완료

---

### [검증 4] 삭제된 이전 패스키로 로그인 시도 시 접근 차단 검증
* **요구사항:** 삭제 처리된 이전 패스키의 Credential ID로 로그인을 시도했을 때, 서버가 미등록 키로 판단하고 즉시 거절(404/401)해야 한다.
* **실행 절차:**
  - 삭제된 1번 패스키의 Credential ID(`cred_card4_primary_win_1791195586877`)를 담아 `POST /api/auth/login-verify` 호출
* **서버 거절 응답 (HTTP 404 Not Found):**
```json
{
  "success": false,
  "message": "서버에 일치하는 등록된 패스키(공개키)가 없습니다."
}
```
* **비인가 상태 확인:** 세션이 발급되지 않으므로 비공개 API(`GET /api/private-data`) 재접근 시 즉시 `401 Unauthorized`로 차단됨을 확인했습니다.

---

## 3. 필수 제출 증빙 항목 (남길 것 4종 전문)

### 1) 패스키 2개가 등록된 관리 화면 및 서버 레코드 목록
```http
GET /api/auth/passkeys HTTP/1.1
Host: localhost:3000

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "success": true,
  "count": 2,
  "passkeys": [
    {
      "id": "cred_card4_primary_win_1791195586877",
      "name": "주 기기: 내 윈도우 PC (Windows Hello)",
      "publicKeyType": "ECC P-256 (ES256 ECDSA Public Key)",
      "authenticatorType": "기기 자체 보안 영역 (Windows Hello / TPM)",
      "registeredAt": "2026-10-05T00:00:00.000Z"
    },
    {
      "id": "cred_card4_backup_iphone_1791195586887",
      "name": "보조 기기: 내 아이폰 (FaceID / iCloud 키체인)",
      "publicKeyType": "ECC P-256 (ES256 ECDSA Public Key)",
      "authenticatorType": "외부/모바일 플랫폼 인증기 (FaceID / iCloud 키체인)",
      "registeredAt": "2026-10-05T00:00:00.000Z"
    }
  ]
}
```

---

### 2) 1개 패스키를 삭제하는 요청 및 처리 완료 로그
```http
DELETE /api/auth/passkeys/cred_card4_primary_win_1791195586877 HTTP/1.1
Host: localhost:3000

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "success": true,
  "message": "패스키 \"주 기기: 내 윈도우 PC (Windows Hello)\"이(가) 정상적으로 삭제되었습니다.",
  "remainingCount": 1
}
```

---

### 3) 삭제된 패스키로 로그인을 시도했을 때 거절되는 요청/응답 로그
```http
POST /api/auth/login-verify HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "credentialId": "cred_card4_primary_win_1791195586877",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi...",
  "authenticatorData": "o2NmbXRkbm9uZWdhdHRTdG10...",
  "signature": "MEQCIGsP...[삭제된 키의 서명]..."
}

HTTP/1.1 404 Not Found
Content-Type: application/json; charset=utf-8

{
  "success": false,
  "message": "서버에 일치하는 등록된 패스키(공개키)가 없습니다."
}
```

---

### 4) 남아 있는 다른 패스키로 정상 로그인에 성공하는 요청/응답 로그
```http
POST /api/auth/login-verify HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "credentialId": "cred_card4_backup_iphone_1791195586887",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi...",
  "authenticatorData": "o2NmbXRkbm9uZWdhdHRTdG10...",
  "signature": "MEQCIH6W...[보조 키 유효 서명]..."
}

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Set-Cookie: connect.sid=s%3A_z0K...****9mPq; Path=/; HttpOnly; SameSite=Lax

{
  "success": true,
  "message": "🎉 [보조 기기: 내 아이폰 (FaceID / iCloud 키체인)] 패스키(Windows Hello PIN / 지문)로 성공적으로 로그인되었습니다!",
  "user": "최민수",
  "passkey": {
    "id": "cred_card4_backup_iphone_1791195586887",
    "name": "보조 기기: 내 아이폰 (FaceID / iCloud 키체인)",
    "authenticatorType": "외부/모바일 플랫폼 인증기 (FaceID / iCloud 키체인)"
  }
}
```

---

## 4. 보안 설계 및 분실 대비 무중단 인증 아키텍처 분석

### 1) 기기 분실과 단일 장애점(SPOF) 방어
비밀번호가 없는 순수 패스키 시스템의 가장 큰 우려는 **"인증 기기를 분실하거나 파손했을 때 계정이 영구적으로 잠기는(Account Lockout) 문제"**입니다.
이를 방지하기 위해 본 시스템은 다음과 같은 3계층 다중화 모델을 구현했습니다:
- **주 기기 (Primary Device):** 업무용 PC의 하드웨어 보안 모듈(TPM 2.0 / Windows Hello)
- **보조 기기 (Secondary Device):** 개인 스마트폰(iOS FaceID / iCloud 키체인) 또는 Android(Google 비밀번호 관리자)
- **비상 복구 (Fallback Key):** 물리 FIDO2 하드웨어 보안키(YubiKey) 추가 등록 지원

### 2) 서버 측 암호학적 해지(Cryptographic Revocation) 원리
- 사용자가 기기를 분실했을 때 웹 관리 화면에서 `[🗑️ 삭제]`를 누르면, 서버 저장소(`passkeys.json`)에서 해당 기기의 Credential ID와 Public Key가 즉시 영구 파기됩니다.
- 분실된 기기를 습득한 공격자가 기기의 생체인증이나 로컬 PIN을 우회하여 유효한 전자서명을 생성하더라도, **서버에 검증할 공개키가 존재하지 않으므로** `404/401`로 즉각 거절됩니다.

---

## 5. 자동화 테스트 결과 (`test_card4.js`)
* **테스트 스크립트:** `test_card4.js`
* **검증 결과:** **14/14 항목 전체 통과 완료 (PASS)**
  - `PASS` [다중 등록: 1번 주 기기 패스키 등록 완료 (HTTP 201)]
  - `PASS` [다중 등록: 2번 보조 기기 패스키 등록 완료 (HTTP 201)]
  - `PASS` [다중 패스키 목록 조회 성공 (HTTP 200)]
  - `PASS` [서버에 등록된 패스키가 2개 이상임 확인]
  - `PASS` [등록된 패스키 2개가 각각 고유한 명칭과 ID로 목록에 노출됨]
  - `PASS` [패스키 삭제 요청 성공 (HTTP 200 OK)]
  - `PASS` [삭제된 1번 패스키가 서버 저장소에서 완전히 제거되었음을 입증]
  - `PASS` [삭제되지 않은 2번 패스키는 저장소에 정상 보존되어 있음을 입증]
  - `PASS` [남은 패스키 로그인 질문(Challenge) 발급 성공]
  - `PASS` [서버의 로그인 허용 패스키 목록에 2번 패스키가 포함됨]
  - `PASS` [서버의 로그인 허용 패스키 목록에서 삭제된 1번 패스키가 제외됨]
  - `PASS` [남은 2번 패스키로 로그인 성공 (HTTP 200 OK)]
  - `PASS` [남은 패스키 로그인 세션으로 비공개 데이터 정상 인가 확인 (HTTP 200)]
  - `PASS` [삭제된 패스키 로그인 시도 시 서버가 거절 응답 반환 (HTTP 404)]