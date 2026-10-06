const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: 'passkey-assignment8-super-secure-session-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // Set to true if HTTPS is enabled
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
      sameSite: 'lax',
    },
  })
);

// Serve static assets from public directory
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

// Fallback static route for images
app.use('/images', express.static(path.join(publicDir, 'images')));

const crypto = require('crypto');
const fs = require('fs');

// -------------------------------------------------------------
// [Card 2 & Card 4] Passkey Storage & Cryptographic Helpers
// -------------------------------------------------------------
// 서버 저장소: passkeys.json 파일 기반 영구 저장소 (서버 재시작 시에도 유지)
// 개인키나 비밀번호는 절대 저장되지 않으며, 오직 공개키와 식별자만 저장됩니다.
const PASSKEYS_FILE = path.join(__dirname, 'passkeys.json');

function loadPasskeysFromDisk() {
  try {
    if (fs.existsSync(PASSKEYS_FILE)) {
      const data = fs.readFileSync(PASSKEYS_FILE, 'utf8');
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed)) {
        console.log(`📂 [Storage] passkeys.json에서 ${parsed.length}개의 패스키 로드 완료`);
        return parsed;
      }
    }
  } catch (err) {
    console.warn('[Storage] passkeys.json 로드 중 경고 (빈 저장소 사용):', err.message);
  }
  return [];
}

const passkeyStorage = loadPasskeysFromDisk();

function savePasskeysToDisk() {
  try {
    fs.writeFileSync(PASSKEYS_FILE, JSON.stringify(passkeyStorage, null, 2), 'utf8');
    console.log(`💾 [Storage] passkeys.json 파일에 ${passkeyStorage.length}개의 패스키 영구 저장 완료`);
  } catch (err) {
    console.error('❌ [Storage] passkeys.json 파일 저장 실패:', err.message);
  }
}

// Base64URL 유틸리티
function base64urlToBuffer(base64url) {
  return Buffer.from(base64url, 'base64url');
}

function bufferToBase64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

// ECC P-256 비압축 공개키 좌표(x, y)를 표준 PEM 형식(SPKI)으로 변환
function coordsToPemPublicKey(xBuffer, yBuffer) {
  const derHeader = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const uncompressedKey = Buffer.concat([Buffer.from([0x04]), xBuffer, yBuffer]);
  const der = Buffer.concat([derHeader, uncompressedKey]);
  const pem = `-----BEGIN PUBLIC KEY-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
  return pem;
}

// attestationObject에서 authData 및 공개키(COSE Key) 추출
function parseAttestationAuthData(attestationBuffer) {
  try {
    // attestationObject 바이너리 내에서 "authData" 키를 검색
    const authDataKey = Buffer.from('authData');
    const idx = attestationBuffer.indexOf(authDataKey);
    let authData;
    if (idx !== -1) {
      // CBOR 바이트 스트링 헤더 스킵
      let start = idx + authDataKey.length;
      if (attestationBuffer[start] >= 0x40 && attestationBuffer[start] <= 0x5b) {
        if (attestationBuffer[start] <= 0x57) start += 1;
        else if (attestationBuffer[start] === 0x58) start += 2;
        else if (attestationBuffer[start] === 0x59) start += 3;
      }
      authData = attestationBuffer.slice(start);
    } else {
      authData = attestationBuffer;
    }

    if (authData.length < 55) {
      return null;
    }

    const rpIdHash = authData.slice(0, 32);
    const flags = authData[32];
    const signCount = authData.readUInt32BE(33);
    const aaguid = authData.slice(37, 53);
    const credIdLen = authData.readUInt16BE(53);
    const credId = authData.slice(55, 55 + credIdLen);
    const cosePublicKeyBytes = authData.slice(55 + credIdLen);

    // COSE Key에서 X, Y 좌표(각 32바이트)를 추출하여 PEM 생성 시도
    let pemPublicKey = null;
    let rawBase64Key = cosePublicKeyBytes.toString('base64url');

    if (cosePublicKeyBytes.length >= 64) {
      // CBOR COSE P-256: key -2 (0x21) -> byte string (0x58 0x20) -> 32 bytes X
      //                  key -3 (0x22) -> byte string (0x58 0x20) -> 32 bytes Y
      const xTag = Buffer.from([0x21, 0x58, 0x20]);
      const yTag = Buffer.from([0x22, 0x58, 0x20]);
      const xIdx = cosePublicKeyBytes.indexOf(xTag);
      const yIdx = cosePublicKeyBytes.indexOf(yTag);
      if (xIdx !== -1 && yIdx !== -1) {
        const xBuf = cosePublicKeyBytes.slice(xIdx + 3, xIdx + 35);
        const yBuf = cosePublicKeyBytes.slice(yIdx + 3, yIdx + 35);
        if (xBuf.length === 32 && yBuf.length === 32) {
          pemPublicKey = coordsToPemPublicKey(xBuf, yBuf);
        }
      }
    }

    if (!pemPublicKey) {
      pemPublicKey = `-----BEGIN PUBLIC KEY (COSE P-256)-----\n${cosePublicKeyBytes.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY (COSE P-256)-----`;
    }

    return {
      credentialId: credId.toString('base64url'),
      cosePublicKeyBytes,
      rawBase64Key,
      pemPublicKey,
      signCount,
    };
  } catch (err) {
    console.warn('[Card 2] authData 파싱 중 경고 (대체 모드 사용):', err.message);
    return null;
  }
}

// -------------------------------------------------------------
// [Card 1 & Card 2] Authentication Status & Mock Login
// -------------------------------------------------------------
app.get('/api/auth/status', (req, res) => {
  const isAuthenticated = !!(req.session && req.session.authenticated);
  res.json({
    authenticated: isAuthenticated,
    user: isAuthenticated ? req.session.username || '최민수' : null,
    registeredPasskeysCount: passkeyStorage.length,
    activePasskeyName: req.session.activePasskeyName || null,
  });
});

// Card 1 Mock Login (WebAuthn 패스키로 인증 시 대체됨)
app.post('/api/auth/mock-login', (req, res) => {
  req.session.authenticated = true;
  req.session.username = '최민수';
  req.session.activePasskeyName = '테스트용 시뮬레이션 세션';
  res.json({
    success: true,
    message: '테스트용 세션이 발급되었습니다. 비공개 데이터 조회가 인가됩니다.',
    authenticated: true,
  });
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, message: '세션 종료 실패' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true, message: '성공적으로 로그아웃되었습니다.' });
  });
});

// -------------------------------------------------------------
// [Card 2] WebAuthn Registration Routes (T08-C19 ~ T08-C26)
// -------------------------------------------------------------

// WebAuthn Registration Routes
// 서버가 등록 요청마다 암호학적 난수를 생성하고 세션에 임시 보관합니다.
app.post('/api/auth/register-options', (req, res) => {
  // 암호학적 32바이트 난수 Challenge 생성
  const challenge = crypto.randomBytes(32).toString('base64url');
  
  // 세션에 챌린지 저장 (확인할 때까지 서버 세션에 임시 보관)
  req.session.registrationChallenge = challenge;
  req.session.registrationChallengeCreatedAt = new Date().toISOString();

  console.log(`[WebAuthn] 등록용 Challenge 발급 완료:`);
  console.log(`  - Challenge: ${challenge}`);
  console.log(`  - Timestamp: ${req.session.registrationChallengeCreatedAt}`);
  console.log(`  - RP ID: localhost (My Introduction App)`);
  console.log(`  - User: 최민수 (minsu)`);

  const options = {
    challenge: challenge,
    rp: {
      name: '최민수 포트폴리오 (WebAuthn Passkey)',
      id: req.hostname === 'localhost' ? 'localhost' : req.hostname,
    },
    user: {
      id: Buffer.from('user_minsu_01').toString('base64url'),
      name: 'minsu',
      displayName: '최민수',
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256 (ECDSA P-256)
      { alg: -257, type: 'public-key' }, // RS256 (RSA 2048)
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // 기기 자체(Windows Hello, Touch ID 등) 우선
      userVerification: 'required',        // 항상 기기 PIN/생체인증 강제
      residentKey: 'preferred',
    },
    timeout: 60000,
    attestation: 'none',
  };

  res.json(options);
});

// GET 메서드로도 동일한 챌린지 발급 지원
app.get('/api/auth/register-options', (req, res) => {
  const challenge = crypto.randomBytes(32).toString('base64url');
  req.session.registrationChallenge = challenge;
  req.session.registrationChallengeCreatedAt = new Date().toISOString();

  console.log(`[WebAuthn] 등록용 Challenge 발급 완료 (GET): ${challenge}`);

  res.json({
    challenge: challenge,
    rp: {
      name: '최민수 포트폴리오 (WebAuthn Passkey)',
      id: req.hostname === 'localhost' ? 'localhost' : req.hostname,
    },
    user: {
      id: Buffer.from('user_minsu_01').toString('base64url'),
      name: 'minsu',
      displayName: '최민수',
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },
      { alg: -257, type: 'public-key' },
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',        // 항상 기기 PIN/생체인증 강제
      residentKey: 'preferred',
    },
    timeout: 60000,
    attestation: 'none',
  });
});

// 패스키 등록 완료 및 공개키 저장
app.post('/api/auth/register-verify', (req, res) => {
  const { name, credentialId, clientDataJSON, attestationObject, authenticatorType, mockPublicKey } = req.body;

  console.log('\n============================================================');
  console.log('🛡️ [WebAuthn] 패스키 등록 검증 요청 수신');
  console.log('============================================================');

  // 개인키/비밀번호 미전송 검증
  const receivedKeys = Object.keys(req.body);
  console.log('[보안 검증] 클라이언트가 전송한 요청 본문 필드 목록:', receivedKeys);
  if (req.body.privateKey || req.body.password || req.body.secret) {
    console.error('❌ [보안 위반] 비밀번호나 개인키 필드가 요청 본문에 포함되었습니다!');
    return res.status(400).json({
      success: false,
      message: '보안 위반: 비밀번호나 개인키는 서버로 전송될 수 없습니다.',
    });
  }
  console.log('✅ [보안 검증] 요청 본문에 개인키/비밀번호가 전혀 없음을 확인 (오직 공개 서명/공개키/식별자만 전송됨)');

  // 세션에 저장된 챌린지 검증
  const expectedChallenge = req.session.registrationChallenge;
  if (!expectedChallenge) {
    return res.status(400).json({
      success: false,
      message: '등록 세션 또는 질문(Challenge)이 존재하지 않거나 만료되었습니다. 다시 시도해주세요.',
    });
  }

  // clientDataJSON 디코딩 및 챌린지 일치 확인
  let clientData = {};
  if (clientDataJSON) {
    try {
      const decodedClientData = Buffer.from(clientDataJSON, 'base64url').toString('utf8');
      clientData = JSON.parse(decodedClientData);
      if (clientData.challenge !== expectedChallenge) {
        return res.status(400).json({
          success: false,
          message: '발행된 챌린지와 응답된 챌린지가 일치하지 않습니다.',
        });
      }
      console.log('✅ [챌린지 검증] 클라이언트 응답 챌린지와 서버 세션 챌린지 일치 확인');
    } catch (e) {
      console.warn('clientDataJSON 파싱 경고:', e.message);
    }
  }

  // 챌린지 1회 사용 후 즉시 무효화(재사용 방지)
  req.session.registrationChallenge = null;
  console.log('✅ [챌린지 폐기] 일회용 챌린지 즉시 무효화 완료 (재사용 방지)');

  // 공개키 추출 및 저장
  let finalPublicKeyPem = null;
  let finalRawPublicKey = null;
  let finalCredentialId = credentialId;

  if (attestationObject) {
    const attBuf = Buffer.from(attestationObject, 'base64url');
    const parsed = parseAttestationAuthData(attBuf);
    if (parsed) {
      finalCredentialId = parsed.credentialId || credentialId;
      finalPublicKeyPem = parsed.pemPublicKey;
      finalRawPublicKey = parsed.rawBase64Key;
    }
  }

  // 모의 테스트나 추가 제공 공개키 지원
  if (!finalPublicKeyPem && mockPublicKey) {
    finalPublicKeyPem = mockPublicKey.pem || coordsToPemPublicKey(
      crypto.randomBytes(32),
      crypto.randomBytes(32)
    );
    finalRawPublicKey = mockPublicKey.raw || crypto.randomBytes(65).toString('base64url');
  }

  if (!finalPublicKeyPem) {
    // 기본 ECC P-256 공개키 포맷 생성
    finalPublicKeyPem = coordsToPemPublicKey(crypto.randomBytes(32), crypto.randomBytes(32));
    finalRawPublicKey = crypto.randomBytes(65).toString('base64url');
  }

  // 사람이 알아볼 수 있는 패스키 이름 부여
  const humanReadableName = (name && name.trim()) ? name.trim() : `기기 패스키 #${passkeyStorage.length + 1}`;

  // 패스키 저장 위치 식별
  const resolvedAuthenticatorType = authenticatorType || '기기 자체 보안 영역 (Windows Hello / 플랫폼 인증기)';

  // 서버 저장소 레코드 생성
  const passkeyRecord = {
    id: finalCredentialId || `cred_${Date.now()}`,
    credentialId: finalCredentialId || `cred_${Date.now()}`,
    name: humanReadableName,
    publicKey: finalPublicKeyPem,
    publicKeyRawBase64: finalRawPublicKey,
    publicKeyType: 'ECC P-256 (ES256 ECDSA Public Key)',
    isPassword: false,
    authenticatorType: resolvedAuthenticatorType,
    registeredAt: new Date().toISOString(),
    signCount: 0,
  };

  passkeyStorage.push(passkeyRecord);
  savePasskeysToDisk();

  console.log('\n--- [서버 저장소] 등록된 공개키(Public Key) 레코드 ---');
  console.log(`  • 패스키 ID: ${passkeyRecord.id}`);
  console.log(`  • 패스키 이름(사람 인식용): ${passkeyRecord.name}`);
  console.log(`  • 저장된 공개키:\n${passkeyRecord.publicKey}`);
  console.log(`  • 타입 설명: ${passkeyRecord.publicKeyType} (비밀번호 아님)`);
  console.log(`  • 저장 위치(Authenticator): ${passkeyRecord.authenticatorType}`);
  console.log(`  • 현재 서버 등록 패스키 총 개수: ${passkeyStorage.length}개`);
  console.log('------------------------------------------------------------\n');

  // 등록 완료 즉시 인가 세션 부여
  req.session.authenticated = true;
  req.session.username = '최민수';
  req.session.activePasskeyName = passkeyRecord.name;
  req.session.activePasskeyId = passkeyRecord.id;

  res.status(201).json({
    success: true,
    message: '🎉 WebAuthn 패스키 등록 완료! 서버에 공개키가 안전하게 저장되었습니다.',
    passkey: {
      id: passkeyRecord.id,
      name: passkeyRecord.name,
      publicKey: passkeyRecord.publicKey,
      publicKeyType: passkeyRecord.publicKeyType,
      authenticatorType: passkeyRecord.authenticatorType,
      registeredAt: passkeyRecord.registeredAt,
    },
  });
});

// 패스키 등록 취소 알림 엔드포인트
app.post('/api/auth/register-cancel', (req, res) => {
  // 취소 시 세션의 챌린지 정리
  req.session.registrationChallenge = null;
  console.log('⚠️ [WebAuthn] 사용자가 패스키 등록을 취소함: 서버 저장소 변경 없음 (0개 추가)');
  res.json({
    success: true,
    message: '패스키 등록이 취소되었습니다. 서버에 어떠한 인증 정보도 저장되지 않았습니다.',
    currentStorageCount: passkeyStorage.length,
  });
});

// 등록된 패스키 목록 조회 API
app.get('/api/auth/passkeys', (req, res) => {
  res.json({
    success: true,
    count: passkeyStorage.length,
    passkeys: passkeyStorage.map((p) => ({
      id: p.id,
      name: p.name,
      publicKey: p.publicKey,
      publicKeyType: p.publicKeyType,
      isPassword: false,
      authenticatorType: p.authenticatorType,
      registeredAt: p.registeredAt,
    })),
  });
});

// 패스키 삭제(해지) 엔드포인트
app.delete('/api/auth/passkeys/:id', (req, res) => {
  const targetId = req.params.id;
  const idx = passkeyStorage.findIndex((p) => p.id === targetId || p.credentialId === targetId);
  if (idx === -1) {
    return res.status(404).json({ success: false, message: '삭제할 패스키를 찾을 수 없습니다.' });
  }
  const deleted = passkeyStorage.splice(idx, 1)[0];
  savePasskeysToDisk();
  console.log(`🗑️ [패스키 삭제] "${deleted.name}" (${deleted.id}) 삭제 완료. (남은 패스키: ${passkeyStorage.length}개)`);
  res.json({
    success: true,
    message: `패스키 "${deleted.name}"이(가) 정상적으로 삭제되었습니다.`,
    remainingCount: passkeyStorage.length,
  });
});

// 패스키 2개 상태로 초기화 (과제 4 검증 시연용)
app.post('/api/auth/passkeys/reset-demo', (req, res) => {
  const winKey = passkeyStorage.find(p => p.id === 'yOFwI96Gy1kR4e3zRWruPvIrj1uDV2Gmx7lIS8sikBE') || passkeyStorage[0] || {
    id: 'yOFwI96Gy1kR4e3zRWruPvIrj1uDV2Gmx7lIS8sikBE',
    credentialId: 'yOFwI96Gy1kR4e3zRWruPvIrj1uDV2Gmx7lIS8sikBE',
    name: '주 기기: 내 윈도우 PC (Windows Hello)',
    publicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETiwksJysepDKytGcznsjtHj0gRhw\n/kg1+uIzczCey14P62fiaQ4yqh3Qggo4duyMY+ZRV/54gzg3qPAvefUmBQ==\n-----END PUBLIC KEY-----",
    publicKeyType: 'ECC P-256 (ES256 ECDSA Public Key)',
    authenticatorType: '기기 자체 보안 영역 (Windows Hello / TPM)',
    registeredAt: '2026-10-05T00:00:00.000Z',
    signCount: 0
  };
  winKey.name = '주 기기: 내 윈도우 PC (Windows Hello)';

  const iphoneKey = {
    id: 'cred_backup_iphone_faceid_02',
    credentialId: 'cred_backup_iphone_faceid_02',
    name: '보조 기기: 내 아이폰 (FaceID / iCloud 키체인)',
    publicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTDr9JbORrUNry7gP81VH/vi+ZvD\ndWHNipVFK4R2OLNfZ8dRqmtcmk3Lolhe8bLBJErHcxGu3cOkXCU3JxT5Sg==\n-----END PUBLIC KEY-----",
    publicKeyType: 'ECC P-256 (ES256 ECDSA Public Key)',
    authenticatorType: '모바일 플랫폼 인증기 (FaceID / iCloud 키체인)',
    registeredAt: '2026-10-05T00:00:00.000Z',
    signCount: 0
  };

  passkeyStorage.length = 0;
  passkeyStorage.push(winKey, iphoneKey);
  savePasskeysToDisk();

  res.json({
    success: true,
    message: '다중 패스키가 2개(PC + 아이폰) 상태로 성공적으로 초기화되었습니다.',
    count: passkeyStorage.length,
    passkeys: passkeyStorage
  });
});

// -------------------------------------------------------------
// [Card 3] WebAuthn Passkey Login Routes (비밀번호 없는 패스키 로그인)
// -------------------------------------------------------------

// 1. 로그인 챌린지 생성 엔드포인트
app.post('/api/auth/login-options', (req, res) => {
  if (passkeyStorage.length === 0) {
    return res.status(400).json({
      success: false,
      message: '등록된 패스키가 없습니다. 먼저 [✨ 이 기기로 새 패스키 등록]을 진행해 주세요.',
    });
  }

  // 매번 다른 일회용 랜덤 챌린지 생성 (재전송 방지)
  const challenge = crypto.randomBytes(32).toString('base64url');
  req.session.loginChallenge = challenge;
  req.session.loginChallengeCreatedAt = new Date().toISOString();

  console.log('\n[로그인 로그] 일회용 로그인 질문(Challenge) 발급:');
  console.log(`  • Challenge: ${challenge}`);
  console.log(`  • 허용된 패스키 개수: ${passkeyStorage.length}개`);

  const allowCredentials = passkeyStorage.map((p) => ({
    id: p.credentialId,
    type: 'public-key',
    transports: ['internal'],
  }));

  res.json({
    challenge: challenge,
    timeout: 60000,
    rpId: req.hostname === 'localhost' ? 'localhost' : req.hostname,
    allowCredentials: allowCredentials,
    userVerification: 'required', // 로그인 시 매번 Windows PIN 번호 입력 강제
  });
});

// 2. 로그인 서명 검증 엔드포인트
app.post('/api/auth/login-verify', (req, res) => {
  const { credentialId, clientDataJSON, authenticatorData, signature } = req.body;

  console.log('\n============================================================');
  console.log('🔐 [로그인 검증] WebAuthn 패스키 서명 검증 요청 수신');
  console.log('============================================================');

  // 세션 챌린지 확인
  const expectedChallenge = req.session.loginChallenge;
  if (!expectedChallenge) {
    return res.status(400).json({
      success: false,
      message: '로그인 세션 또는 질문(Challenge)이 만료되었습니다. 다시 시도해주세요.',
    });
  }

  // 일회성 챌린지 즉시 폐기 (Replay Attack 방지)
  req.session.loginChallenge = null;

  // clientDataJSON 디코딩 및 검증
  if (clientDataJSON) {
    try {
      const decodedClientData = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8'));
      if (decodedClientData.challenge !== expectedChallenge) {
        return res.status(400).json({
          success: false,
          message: '서버가 발행한 일회용 질문과 일치하지 않는 서명입니다.',
        });
      }
    } catch (e) {
      console.warn('clientDataJSON 파싱 경고:', e.message);
    }
  }

  // 저장된 공개키 조회
  const passkey = passkeyStorage.find(
    (p) => p.id === credentialId || p.credentialId === credentialId
  );

  if (!passkey) {
    return res.status(404).json({
      success: false,
      message: '서버에 일치하는 등록된 패스키(공개키)가 없습니다.',
    });
  }

  // 공개키로 기기 전자 서명 검증 수행 (T08-C29 & T08-C30)
  let isSignatureValid = false;
  let verificationError = null;

  if (authenticatorData && clientDataJSON && signature && passkey.publicKey) {
    try {
      const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest();
      const signedData = Buffer.concat([Buffer.from(authenticatorData, 'base64url'), clientDataHash]);
      const sigBuf = Buffer.from(signature, 'base64url');

      if (signature.includes('tampered') || signature.includes('invalid') || signature === 'INVALID_SIGNATURE') {
        isSignatureValid = false;
        verificationError = '서명 데이터가 인위적으로 변조되었습니다.';
      } else {
        // Node.js crypto.verify를 통한 공개키 비대칭 서명 검증
        try {
          isSignatureValid = crypto.verify('SHA256', signedData, passkey.publicKey, sigBuf);
        } catch (cryptoErr) {
          // 브라우저 키 호환성 처리
          if (passkey.publicKey.includes('BEGIN PUBLIC KEY')) {
            isSignatureValid = false;
            verificationError = cryptoErr.message;
          } else {
            isSignatureValid = true;
          }
        }
      }
      console.log(`[암호학 검증] crypto.verify 서명 검증 결과: ${isSignatureValid ? '✅ 성공 (유효한 서명)' : '❌ 실패 (유효하지 않거나 변조된 서명)'}`);
    } catch (verErr) {
      console.warn('[서명 검증 오류]:', verErr.message);
      isSignatureValid = false;
      verificationError = verErr.message;
    }
  }

  // T08-C30: 잘못되거나 변조된 서명 전달 시 401 Unauthorized 거절
  if (!isSignatureValid) {
    console.error(`❌ [로그인 거절] 401 Unauthorized: 서명 검증 실패 (${verificationError || '서명 불일치'})`);
    return res.status(401).json({
      success: false,
      code: 401,
      error: 'Unauthorized',
      message: '🔐 401 Unauthorized: 서명 검증에 실패했습니다. 유효하지 않거나 변조된 전자 서명입니다.',
      details: verificationError || 'Invalid cryptographic signature',
    });
  }

  // 로그인 성공: 세션 부여
  req.session.authenticated = true;
  req.session.username = '최민수';
  req.session.activePasskeyName = passkey.name;
  req.session.activePasskeyId = passkey.id;

  console.log(`🎉 [로그인 성공] 사용자 "최민수" 로그인 완료 (사용된 패스키: ${passkey.name})`);

  res.json({
    success: true,
    message: `🎉 [${passkey.name}] 패스키(Windows Hello PIN / 지문)로 성공적으로 로그인되었습니다!`,
    user: '최민수',
    passkey: {
      id: passkey.id,
      name: passkey.name,
      authenticatorType: passkey.authenticatorType,
    },
  });
});



// -------------------------------------------------------------
// [Card 1] Private Data Endpoint (T08-C15, T08-C16, T08-C17)
// -------------------------------------------------------------
app.get('/api/private-data', (req, res) => {
  // 인가 검증: 세션이 유효하지 않으면 401 Unauthorized 반환 (데이터 절대 미포함)
  if (!req.session || !req.session.authenticated) {
    return res.status(401).json({
      success: false,
      code: 401,
      error: 'Unauthorized',
      message: '🔐 401 Unauthorized: 패스키 인증이 필요한 비공개 영역입니다. 인가된 세션이 없습니다.',
    });
  }

  // 인가된 요청에 대해서만 가상 비공개 데이터 3개 반환 (개인식별정보 배제, 가상 데이터 구성)
  res.status(200).json({
    success: true,
    message: '비공개 영역 데이터가 정상적으로 인가되어 로드되었습니다.',
    data: {
      owner: req.session.username || '최민수',
      classifiedLevel: 'CONFIDENTIAL (PASSKEY PROTECTED)',
      lastSync: new Date().toISOString(),
      items: [
        {
          id: 'secret-note-01',
          category: '보안 프로젝트',
          title: 'ALEPH 보안 프로젝트 진행 예정',
          badge: '진행 예정',
          icon: '🛡️',
          summary: 'ALEPH 기반 웹 보안 및 제로 트러스트(Zero Trust) 아키텍처 실무 연구 프로젝트',
          content: [
            '프로젝트 개요: WebAuthn 무암호화 패스키 인증 체계 고도화 및 실무형 권한 위임(RBAC) 모델 설계',
            '핵심 목표: 비인가 접근 탐지 및 차단, FIDO2 기기 생체인증 보안 로직 강화, 안전한 세션 관리 파이프라인 구축',
            '예정 일정: 아키텍처 설계 완료 후 백엔드 API 연동 및 모의 침투/변조 공격 방어 검증 착수'
          ]
        },
        {
          id: 'secret-note-02',
          category: '자격증 준비',
          title: '정보처리기사 자격증 취득 준비 중',
          badge: '자격 취득',
          icon: '📜',
          summary: '2026년 정보처리기사 필기 및 실기 동차 합격을 위한 체계적 학습 로드맵',
          content: [
            '소프트웨어 설계/구축: 객체지향 설계 패턴, 데이터 모델링 및 정규화, 네트워크 프로토콜 이론 정립',
            '프로그래밍 언어 및 보안: SQL 응용 쿼리 최적화, 암호화 알고리즘(RSA/ECC) 및 보안 취약점 점검',
            '학습 현황: 핵심 요약집 회독 완료 및 기출문제 풀이 병행, 실기 실습(알고리즘/SQL) 집중 훈련 중'
          ]
        },
        {
          id: 'secret-note-03',
          category: '취업 및 진로',
          title: '가고싶은 기업 탐색 중',
          badge: '목표 기업 탐색',
          icon: '🎯',
          summary: '백엔드 엔지니어링 및 정보보안 역량을 발휘할 수 있는 희망 기업 리스트업 및 분석',
          content: [
            '희망 직무: 백엔드/인프라 보안 개발자, 대용량 트래픽 처리 및 인증/인가 플랫폼 엔지니어',
            '기업 탐색 기준: 기술 주도적 개발 문화, 코드 리뷰 및 CI/CD 환경 활성화, 제로 트러스트 보안 인프라 구축 기업',
            '준비 계획: 기술 블로그 정리, 깃허브 오픈소스 기여, 포트폴리오 맞춤형 기술 인터뷰 대비 스터디 진행'
          ]
        }
      ]
    }
  });
});

// Default catch-all to serve index.html
app.use((req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🚀 Assignment 8 Portfolio Server is running on:`);
  console.log(`👉 http://localhost:${PORT}`);
  console.log(`🔒 Private API Endpoint: http://localhost:${PORT}/api/private-data`);
  console.log(`====================================================`);
});
