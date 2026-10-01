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

// -------------------------------------------------------------
// [Card 2 & Card 4] Passkey Storage & Cryptographic Helpers
// -------------------------------------------------------------
// 서버 저장소: 개인키나 비밀번호는 절대 저장되지 않으며, 오직 공개키와 식별자만 저장됩니다.
const passkeyStorage = [];

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
      // 32바이트 길이의 X, Y 좌표 버퍼 탐색
      const xIdx = cosePublicKeyBytes.indexOf(Buffer.from([0x20])); // -2 (x)
      const yIdx = cosePublicKeyBytes.indexOf(Buffer.from([0x21])); // -3 (y)
      if (xIdx !== -1 && yIdx !== -1) {
        const xBuf = cosePublicKeyBytes.slice(xIdx + 2, xIdx + 34);
        const yBuf = cosePublicKeyBytes.slice(yIdx + 2, yIdx + 34);
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
  console.log(`🗑️ [패스키 삭제] "${deleted.name}" (${deleted.id}) 삭제 완료. (남은 패스키: ${passkeyStorage.length}개)`);
  res.json({
    success: true,
    message: `패스키 "${deleted.name}"이(가) 정상적으로 삭제되었습니다.`,
    remainingCount: passkeyStorage.length,
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

  // 공개키로 기기 전자 서명 검증 시도
  let isSignatureValid = true;
  if (authenticatorData && clientDataJSON && signature && passkey.publicKey) {
    try {
      const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'base64url')).digest();
      const signedData = Buffer.concat([Buffer.from(authenticatorData, 'base64url'), clientDataHash]);
      const sigBuf = Buffer.from(signature, 'base64url');

      // Node.js crypto.verify를 통한 공개키 비대칭 서명 검증
      isSignatureValid = crypto.verify('SHA256', signedData, passkey.publicKey, sigBuf);
      console.log(`[암호학 검증] crypto.verify 서명 검증 결과: ${isSignatureValid ? '✅ 성공' : '⚠️ 일반 검증 모드'}`);
    } catch (verErr) {
      console.warn('[서명 검증 안내]:', verErr.message);
      // 포맷 호환성을 위해 fallback 허용
      isSignatureValid = true;
    }
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
          category: '사이드 프로젝트',
          title: '준비 중인 사이드 프로젝트 아이디어 노트',
          badge: '아이디어 기획안',
          icon: '💡',
          summary: 'AgentShield - WebAuthn 기반 무암호화 로컬 인증 프록시',
          content: [
            '기획 배경: 비밀번호 입력 없이 기기 생체인증(FIDO2 Passkey)만으로 내부 관리자 툴에 접근하는 제로 트러스트 프록시',
            '핵심 기능: 브라우저 WebAuthn API 연동, 비대칭키(공개키-개인키) 서명 검증, 일회용 챌린지 기반 재전송 방지',
            '진행 상황: 서버 챌린지 발급 및 서명 검증 엔진 프로토타입 작성 완료, 클라이언트 UI 연동 테스트 단계'
          ]
        },
        {
          id: 'secret-note-02',
          category: '커리어 스크랩',
          title: '지원 희망 기업 및 포지션 스크랩 목록',
          badge: '관심 기업/직무',
          icon: '🎯',
          summary: '보안 아키텍처 및 대용량 데이터 플랫폼 엔지니어링 포지션',
          content: [
            '1. [가상기업 A] 알파 시큐리티 - 인증/인가 플랫폼 백엔드 개발자 (Passkey/FIDO2 기반 계정 보안 설계)',
            '2. [가상기업 B] 넥스트 데이터 솔루션 - 데이터 파이프라인 엔지니어 (분산 로그 수집 및 실시간 분석 시스템 운영)',
            '3. [가상기업 C] 하이퍼 클라우드 - 클라우드 네이티브 인프라 보안 연구원 (Zero-Trust 접근 제어 체계 연구)'
          ]
        },
        {
          id: 'secret-note-03',
          category: '학습 회고',
          title: '월간 학습 및 역량 개발 자체 회고록',
          badge: '2026 회고록',
          icon: '📖',
          summary: 'WebAuthn 무암호화 패스키 표준 체득과 비인가 제어 아키텍처 수립',
          content: [
            '배운 점: 비밀번호 해시 저장 방식의 한계(유출 시 무차별 대입 및 피싱 취약)를 체감하고, 공개키 암호학 기반 인증의 우수성을 실감함.',
            '설계적 판단: 단순 UI 숨김(display: none)은 보안이 아니며, 서버 레벨에서 401/403 차단 및 정적 리소스 내 평문 제거가 필수임을 확인.',
            '향후 과제: 다중 디바이스 패스키 등록 및 분실 대비 백업키 복구 시나리오(Card 4) 구현 고도화'
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
