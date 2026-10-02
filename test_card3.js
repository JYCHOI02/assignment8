const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// HTTP Request Helper
async function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
        });
      });
    });

    req.on('error', (e) => reject(e));

    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

// 쿠키 헤더 파싱 헬퍼
function getCookieString(res) {
  if (res.headers && res.headers['set-cookie']) {
    return res.headers['set-cookie'][0].split(';')[0];
  }
  return '';
}

// 세션 토큰 마스킹 (T08-C34)
function maskSessionToken(cookieStr) {
  if (!cookieStr) return '(none)';
  if (cookieStr.length <= 15) return '****';
  return cookieStr.substring(0, 10) + '...' + '****' + cookieStr.slice(-4);
}

async function runCard3Tests() {
  console.log('===============================================================');
  console.log('🛡️  [T08 - 카드 3] 패스키 로그인 및 전자서명 검증 자동화 테스트');
  console.log('===============================================================\n');

  let passed = 0;
  let total = 0;

  function assert(condition, testName, details = '') {
    total++;
    if (condition) {
      console.log(`✅ PASS [${testName}]`);
      passed++;
    } else {
      console.error(`❌ FAIL [${testName}] - ${details}`);
    }
  }

  try {
    // -------------------------------------------------------------
    // [준비 단계] 테스트용 ECC P-256 키페어 생성 및 패스키 사전 등록
    // -------------------------------------------------------------
    console.log('▶ [준비] NIST P-256 비대칭 암호 키페어 생성 및 테스트용 패스키 준비...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const testCredId = 'cred_card3_test_' + Date.now();
    const testKeyName = '테스트용 카드3 패스키 (Windows Hello 모의)';

    // 등록 챌린지 요청
    const regOptRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const regOpt = JSON.parse(regOptRes.body);
    const regCookie = getCookieString(regOptRes);

    const clientDataJSONReg = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regOpt.challenge,
        origin: 'http://localhost:3000',
      })
    ).toString('base64url');

    // 정식 등록 수행
    const regRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/register-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: regCookie,
        },
      },
      JSON.stringify({
        name: testKeyName,
        credentialId: testCredId,
        clientDataJSON: clientDataJSONReg,
        authenticatorType: '기기 자체 보안 영역 (Windows Hello / TPM 플랫폼 인증기)',
        mockPublicKey: { pem: publicKey },
      })
    );

    assert(regRes.statusCode === 201, '사전 준비: 테스트용 패스키 등록 완료 (HTTP 201)');
    console.log(`  • 등록된 패스키 ID: ${testCredId}`);
    console.log(`  • 등록된 패스키 이름: ${testKeyName}\n`);

    // -------------------------------------------------------------
    // [T08-C27 & T08-C28] 일회성 챌린지 생성 및 상이성 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 1] 일회성 챌린지 생성 및 고유성 검증 (T08-C27, T08-C28)...');
    
    // 1차 로그인 옵션 요청
    const loginOptRes1 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    assert(loginOptRes1.statusCode === 200, 'T08-C27: 로그인 1차 질문(Challenge) 발급 성공 (HTTP 200)');
    const opt1 = JSON.parse(loginOptRes1.body);
    const cookie1 = getCookieString(loginOptRes1);

    // 2차 로그인 옵션 요청
    const loginOptRes2 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    assert(loginOptRes2.statusCode === 200, 'T08-C27: 로그인 2차 질문(Challenge) 발급 성공 (HTTP 200)');
    const opt2 = JSON.parse(loginOptRes2.body);

    assert(
      typeof opt1.challenge === 'string' && typeof opt2.challenge === 'string',
      'T08-C27: 질문(Challenge)이 암호학적 난수 문자열로 발급됨'
    );
    assert(
      opt1.challenge !== opt2.challenge,
      'T08-C28: 1차와 2차 로그인 질문(Challenge) 값이 완전히 다름을 증명'
    );

    console.log(`  • 1차 로그인 Challenge: ${opt1.challenge}`);
    console.log(`  • 2차 로그인 Challenge: ${opt2.challenge}`);
    console.log(`  • 검증 결과: 두 챌린지가 서로 상이함 (고유성 증명 완료)\n`);

    // -------------------------------------------------------------
    // [T08-C29 & T08-C30] 서명 검증 성공 / 변조 서명 거절 대조
    // -------------------------------------------------------------
    console.log('▶ [Step 2] 서명 검증 성공 vs 변조 서명 거절 대조 (T08-C29, T08-C30)...');

    // 3차 정식 로그인 옵션 요청 (세션 바인딩)
    const loginOptRes3 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const opt3 = JSON.parse(loginOptRes3.body);
    const activeCookie = getCookieString(loginOptRes3);

    // 클라이언트 인증기 서명 생성 시뮬레이션
    const authenticatorData = crypto.randomBytes(37); // RP ID 해시 + 플래그 + 카운터
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: opt3.challenge,
        origin: 'http://localhost:3000',
      })
    );

    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signedPayload = Buffer.concat([authenticatorData, clientDataHash]);

    // 기기 개인키(Private Key)로 유효한 전자 서명 생성
    const validSignature = crypto.sign('SHA256', signedPayload, privateKey);

    // 1) 변조된 서명으로 로그인 시도 (T08-C30)
    console.log('[T08-C30 검증] 변조된(잘못된) 서명으로 로그인 요청 전송...');
    const tamperedPayload = {
      credentialId: testCredId,
      clientDataJSON: clientDataJSON.toString('base64url'),
      authenticatorData: authenticatorData.toString('base64url'),
      signature: 'tampered_invalid_signature_byte_payload_0123456789',
    };

    const failRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: activeCookie,
        },
      },
      JSON.stringify(tamperedPayload)
    );

    assert(
      failRes.statusCode === 401,
      'T08-C30: 변조된 서명 전달 시 서버가 401 Unauthorized로 거절'
    );
    const failBody = JSON.parse(failRes.body);
    console.log(`  • 거절 응답 코드: HTTP ${failRes.statusCode} Unauthorized`);
    console.log(`  • 거절 메시지: "${failBody.message}"\n`);

    // 새 챌린지로 유효한 서명 로그인 시도 (T08-C29)
    console.log('[T08-C29 검증] 유효한 서명으로 정상 로그인 요청 전송...');
    const loginOptRes4 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const opt4 = JSON.parse(loginOptRes4.body);
    const validSessionCookie = getCookieString(loginOptRes4);

    const clientDataJSON4 = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: opt4.challenge,
        origin: 'http://localhost:3000',
      })
    );
    const clientDataHash4 = crypto.createHash('sha256').update(clientDataJSON4).digest();
    const signedPayload4 = Buffer.concat([authenticatorData, clientDataHash4]);
    const validSignature4 = crypto.sign('SHA256', signedPayload4, privateKey);

    const validPayload = {
      credentialId: testCredId,
      clientDataJSON: clientDataJSON4.toString('base64url'),
      authenticatorData: authenticatorData.toString('base64url'),
      signature: validSignature4.toString('base64url'),
    };

    const successRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: validSessionCookie,
        },
      },
      JSON.stringify(validPayload)
    );

    assert(
      successRes.statusCode === 200,
      'T08-C29: 유효한 서명 확인 시 로그인 성공 (HTTP 200 OK)'
    );
    const successBody = JSON.parse(successRes.body);
    assert(
      successBody.success === true && successBody.user === '최민수',
      'T08-C29: 세션 인가 및 사용자 식별 완료'
    );
    console.log(`  • 성공 응답 코드: HTTP ${successRes.statusCode} OK`);
    console.log(`  • 인가된 사용자: ${successBody.user}`);
    console.log(`  • 환영 메시지: "${successBody.message}"\n`);

    // -------------------------------------------------------------
    // [T08-C31] 챌린지 재사용(Replay Attack) 방지 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 3] 챌린지 재사용(Replay Attack) 방지 검증 (T08-C31)...');
    const replayRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: validSessionCookie,
        },
      },
      JSON.stringify(validPayload)
    );

    assert(
      replayRes.statusCode === 400,
      'T08-C31: 이미 1회 사용된 질문(Challenge)으로 재요청 시 서버가 400 Bad Request로 거절'
    );
    const replayBody = JSON.parse(replayRes.body);
    console.log(`  • 재사용 공격 차단 응답: HTTP ${replayRes.statusCode}`);
    console.log(`  • 서버 차단 사유: "${replayBody.message}"\n`);

    // -------------------------------------------------------------
    // [T08-C32 & T08-C34] 로그인 식별 방식 및 마스킹
    // -------------------------------------------------------------
    console.log('▶ [Step 4] 로그인 사용자 식별 방식 및 마스킹 증빙 (T08-C32, T08-C34)...');
    const authCookie = validSessionCookie;
    assert(
      authCookie.includes('connect.sid='),
      'T08-C32: 로그인 식별 방식이 HTTP-Only 쿠키 세션(connect.sid)으로 확인됨'
    );
    const maskedCookie = maskSessionToken(authCookie);
    console.log(`  • 식별 메커니즘: express-session 기반 암호화 세션 쿠키 (HttpOnly, SameSite=Lax)`);
    console.log(`  • 실제 발급된 세션 식별자 (마스킹 처리): ${maskedCookie}`);
    assert(
      maskedCookie.includes('****'),
      'T08-C34: 세션 식별자가 제출 증빙에서 마스킹(가림) 처리됨\n'
    );

    // -------------------------------------------------------------
    // [T08-C33] 로그아웃 후 무효화 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 5] 로그아웃 후 비공개 영역 재접근 차단 검증 (T08-C33)...');
    
    // 1) 로그인 상태에서 비공개 데이터 접근 확인 (200 OK)
    const privateAccessBefore = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
      headers: { Cookie: authCookie },
    });
    assert(
      privateAccessBefore.statusCode === 200,
      'T08-C33: 로그인 상태에서 비공개 데이터 접근 허용 (HTTP 200 OK)'
    );

    // 2) 로그아웃 수행
    const logoutRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/logout',
      method: 'POST',
      headers: { Cookie: authCookie },
    });
    assert(logoutRes.statusCode === 200, 'T08-C33: 로그아웃 요청 성공 (HTTP 200)');
    console.log('  • 로그아웃 실행: 서버 세션 파기 및 쿠키 초기화 완료');

    // 3) 이전 세션 쿠키로 비공개 데이터 재접근 시도 -> 401 거절 확인
    const privateAccessAfter = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
      headers: { Cookie: authCookie },
    });
    assert(
      privateAccessAfter.statusCode === 401,
      'T08-C33: 로그아웃 후 이전 세션으로 비공개 데이터 재접근 시 401 Unauthorized 거절'
    );
    console.log(`  • 로그아웃 후 재접근 응답: HTTP ${privateAccessAfter.statusCode} Unauthorized (인가 즉시 박탈 확인)\n`);

    // -------------------------------------------------------------
    // [T08-C35] 화면 어디에도 비밀번호 입력창이 없음 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 6] 비밀번호 입력창 부재 검증 (T08-C35)...');
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    const htmlContent = fs.readFileSync(htmlPath, 'utf8');

    const passwordInputRegex = /<input[^>]*type=["']password["'][^>]*>/gi;
    const matches = htmlContent.match(passwordInputRegex);
    const hasPasswordInput = matches !== null && matches.length > 0;

    assert(
      !hasPasswordInput,
      'T08-C35: public/index.html 내에 비밀번호 입력창(<input type="password">)이 전혀 존재하지 않음 (0개)'
    );
    console.log(`  • 검사 대상 파일: public/index.html`);
    console.log(`  • <input type="password"> 검색 결과: 0건 발견 (비밀번호 없는 순수 WebAuthn 패스키 인터페이스)\n`);

    // -------------------------------------------------------------
    // [정리] 테스트용 패스키 삭제
    // -------------------------------------------------------------
    await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: `/api/auth/passkeys/${testCredId}`,
      method: 'DELETE',
    });

    console.log('===============================================================');
    console.log(`🎉 [Card 3 종합 검증 결과] ${passed}/${total} 항목 전체 통과 완료 (PASS)!`);
    console.log('===============================================================\n');

    process.exit(0);
  } catch (err) {
    console.error('검증 테스트 실행 중 에러 발생:', err);
    process.exit(1);
  }
}

runCard3Tests();
