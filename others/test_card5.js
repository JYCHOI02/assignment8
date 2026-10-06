const http = require('http');
const crypto = require('crypto');

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

function getCookieString(res) {
  const setCookie = res.headers['set-cookie'];
  if (!setCookie) return '';
  if (Array.isArray(setCookie)) {
    return setCookie.map((c) => c.split(';')[0]).join('; ');
  }
  return setCookie.split(';')[0];
}

async function runCard5Tests() {
  console.log('===============================================================');
  console.log('🛡️  [T08 - 카드 5] 비공개 영역 보호 및 타인 권한 차단 종합 검증 테스트');
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
    // [검증 1] 공개 / 비공개 영역 분리 확인
    // -------------------------------------------------------------
    console.log('▶ [검증 1] 공개 / 비공개 영역 분리 확인...');

    // 1-1. 비인증 상태에서 누구나 볼 수 있는 포트폴리오/소개 첫 화면 (GET /)
    const publicPageRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/',
      method: 'GET',
    });
    assert(
      publicPageRes.statusCode === 200 && publicPageRes.body.includes('최민수'),
      '1-1. 공개 포트폴리오 첫 화면 누구나 접근 가능 (HTTP 200 OK)',
      `Status: ${publicPageRes.statusCode}`
    );

    // 1-2. 공개 API (GET /api/public-info) 비인증 접근 가능
    const publicApiRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/public-info',
      method: 'GET',
    });
    const publicData = JSON.parse(publicApiRes.body);
    assert(
      publicApiRes.statusCode === 200 && publicData.success === true && publicData.area === 'PUBLIC_ZONE',
      '1-2. 공개 프로필 API 비인증 정상 응답 (HTTP 200 OK)',
      `Status: ${publicApiRes.statusCode}`
    );

    // 1-3. 보호된 비공개 경로 (GET /api/private-data) 인증 없이는 접근 불가
    const unauthPrivateRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
    });
    const unauthData = JSON.parse(unauthPrivateRes.body);
    assert(
      unauthPrivateRes.statusCode === 401 && unauthData.code === 401,
      '1-3. 비공개 API 경로 분리 및 인증 강제 확인 (HTTP 401 Unauthorized)',
      `Status: ${unauthPrivateRes.statusCode}`
    );

    // -------------------------------------------------------------
    // [검증 2] 미인증 접근 차단 (세션/토큰 없는 직접 호출 거절)
    // -------------------------------------------------------------
    console.log('\n▶ [검증 2] 미인증 접근 차단 (HTTP 401 Unauthorized 거절 응답)...');

    assert(
      unauthPrivateRes.statusCode === 401 && unauthData.error === 'Unauthorized' && unauthData.message.includes('401 Unauthorized'),
      '2-1. 세션/쿠키 없이 직접 호출 시 401 Unauthorized 거절 응답',
      `Body: ${unauthPrivateRes.body}`
    );
    assert(
      !unauthPrivateRes.body.includes('ALEPH 보안 프로젝트') && !unauthPrivateRes.body.includes('정보처리기사'),
      '2-2. 401 거절 시 비공개 데이터 텍스트 전무 확인 (데이터 누출 차단)',
      `Leaked private text found in body!`
    );

    // -------------------------------------------------------------
    // [검증 3] 타인 패스키(비인가 인증) 차단 입증
    // -------------------------------------------------------------
    console.log('\n▶ [검증 3] 타인 패스키(비인가 인증) 차단 입증...');

    // 3-1. 서버에 등록되지 않은 제3자/공격자 Credential ID 제출 시 거절
    const loginOptRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const loginOpt = JSON.parse(loginOptRes.body);
    const loginCookie = getCookieString(loginOptRes);

    const unregisteredPayload = JSON.stringify({
      credentialId: 'cred_attacker_unregistered_key_99999',
      clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: loginOpt.challenge, origin: 'http://localhost:3000' })).toString('base64url'),
      authenticatorData: 'o2NmbXRkbm9uZWdhdHRTdG10',
      signature: 'attacker_fake_signature_bytes_0123456789'
    });

    const unregRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(unregisteredPayload),
          Cookie: loginCookie,
        },
      },
      unregisteredPayload
    );
    const unregData = JSON.parse(unregRes.body);

    assert(
      unregRes.statusCode === 404 || unregRes.statusCode === 401,
      '3-1. 서버 미등록 타인/공격자 키 쌍 제출 시 거절 응답 (HTTP 404/401)',
      `Status: ${unregRes.statusCode}, Body: ${unregRes.body}`
    );

    // 3-2. 등록된 크리덴셜 ID이지만 타인/공격자 개인키로 서명된 변조/불일치 서명 제출 시 401 거절
    const loginOptRes2 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const loginOpt2 = JSON.parse(loginOptRes2.body);
    const loginCookie2 = getCookieString(loginOptRes2);
    const targetCredId = loginOpt2.allowCredentials[0].id;

    // 타인 공격자가 임의로 생성한 별도 EC 키페어로 서명
    const attackerKeyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const clientDataBytes = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: loginOpt2.challenge, origin: 'http://localhost:3000' }));
    const authDataBytes = Buffer.from('o2NmbXRkbm9uZWdhdHRTdG10', 'base64url');
    const clientDataHash = crypto.createHash('sha256').update(clientDataBytes).digest();
    const signedData = Buffer.concat([authDataBytes, clientDataHash]);

    const attackerSign = crypto.createSign('SHA256');
    attackerSign.update(signedData);
    const attackerSigBuf = attackerSign.sign(attackerKeyPair.privateKey);

    const tamperedPayload = JSON.stringify({
      credentialId: targetCredId,
      clientDataJSON: clientDataBytes.toString('base64url'),
      authenticatorData: authDataBytes.toString('base64url'),
      signature: attackerSigBuf.toString('base64url')
    });

    const tamperedRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(tamperedPayload),
          Cookie: loginCookie2,
        },
      },
      tamperedPayload
    );
    const tamperedData = JSON.parse(tamperedRes.body);

    assert(
      tamperedRes.statusCode === 401 && tamperedData.code === 401 && tamperedData.error === 'Unauthorized',
      '3-2. 타인 개인키로 서명된 서명 제출 시 401 Unauthorized 거절 응답',
      `Status: ${tamperedRes.statusCode}`
    );

    // 3-3. 타인 계정의 패스키로 내 비공개 영역 데이터 열람 시도 시 403 Forbidden 거절
    console.log('\n▶ [검증 3-3] 타인 계정 패스키로 내 비공개 영역 열람 시도 (HTTP 403 Forbidden 거절 응답)...');
    
    // 공격자 계정(attacker_bob)으로 유효한 로그인 세션 생성
    const attackerLoginRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/mock-attacker-login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const attackerSessionCookie = getCookieString(attackerLoginRes);

    // 공격자 세션으로 '최민수'의 비공개 데이터 접근 시도 (GET /api/private-data?userId=minsu)
    const crossAccessRes1 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data?userId=minsu',
      method: 'GET',
      headers: { Cookie: attackerSessionCookie },
    });
    const crossAccessData1 = JSON.parse(crossAccessRes1.body);

    assert(
      crossAccessRes1.statusCode === 403 && crossAccessData1.code === 403 && crossAccessData1.error === 'Forbidden',
      '3-3-A. 쿼리 파라미터(?userId=minsu) 타인 비공개 데이터 접근 시 403 Forbidden 거절',
      `Status: ${crossAccessRes1.statusCode}, Body: ${crossAccessRes1.body}`
    );

    // 공격자 세션으로 경로 분기 (/api/users/minsu/private-data) 타인 비공개 데이터 접근 시도
    const crossAccessRes2 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/users/minsu/private-data',
      method: 'GET',
      headers: { Cookie: attackerSessionCookie },
    });
    const crossAccessData2 = JSON.parse(crossAccessRes2.body);

    assert(
      crossAccessRes2.statusCode === 403 && crossAccessData2.code === 403 && crossAccessData2.error === 'Forbidden',
      '3-3-B. REST 경로(/api/users/minsu/private-data) 타인 비공개 데이터 접근 시 403 Forbidden 거절',
      `Status: ${crossAccessRes2.statusCode}, Body: ${crossAccessRes2.body}`
    );

    // 공격자 세션 정리(로그아웃)
    await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/logout',
      method: 'POST',
      headers: { Cookie: attackerSessionCookie },
    });

    // -------------------------------------------------------------
    // [검증 4] 본인 패스키 정상 인가 및 민감정보 부재 확인
    // -------------------------------------------------------------
    console.log('\n▶ [검증 4] 본인 패스키 정상 인가 및 민감정보 부재 확인...');

    // 4-1. 본인 정상 세션 발급
    const authRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/mock-login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const authCookie = getCookieString(authRes);

    // 4-2. 본인 비공개 데이터 조회 (HTTP 200 OK)
    const privateRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
      headers: { Cookie: authCookie },
    });
    const privateData = JSON.parse(privateRes.body);

    assert(
      privateRes.statusCode === 200 && privateData.success === true && Array.isArray(privateData.data.items) && privateData.data.items.length === 3,
      '4-1. 정당한 본인 세션으로 비공개 데이터 3종 정상 열람 (HTTP 200 OK)',
      `Status: ${privateRes.statusCode}`
    );

    // 4-3. 비공개 데이터 내 민감정보 부재 감사
    const rawDataString = JSON.stringify(privateData);
    const hasResidentNumber = /\d{6}-[1-4]\d{6}/.test(rawDataString);
    const hasRealPhone = /010-\d{4}-\d{4}/.test(rawDataString);

    assert(
      !hasResidentNumber && !hasRealPhone && privateData.data.privacyAudit.containsRealPII === false,
      '4-2. 비공개 데이터 내 실제 주민등록번호/전화번호 미포함 및 목업 데이터 사용 확인',
      `containsRealPII: ${privateData.data.privacyAudit.containsRealPII}`
    );

    // 4-4. 전용 민감정보 감사 엔드포인트 (/api/auth/privacy-audit) 확인
    const auditRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/privacy-audit',
      method: 'GET',
    });
    const auditData = JSON.parse(auditRes.body);

    assert(
      auditRes.statusCode === 200 && auditData.auditStatus === 'VERIFIED_CLEAN' && auditData.containsRealPII === false,
      '4-3. 전용 보안 감사 엔드포인트(/api/auth/privacy-audit) 무결성 통과 (HTTP 200 OK)',
      `Status: ${auditRes.statusCode}`
    );

    console.log('\n===============================================================');
    console.log(`📊 [최종 검증 결과] 총 ${total}개 검증 항목 중 ${passed}개 통과 (성공률: ${Math.round((passed / total) * 100)}%)`);
    console.log('===============================================================');

    if (passed === total) {
      console.log('🎉 [T08 - 카드 5] 모든 비공개 영역 보호 및 타인 권한 차단 검증 100% 통과!');
      process.exit(0);
    } else {
      console.error('❌ 일부 검증 항목이 실패하였습니다.');
      process.exit(1);
    }
  } catch (err) {
    console.error('❌ 테스트 실행 중 치명적 예외 발생:', err);
    process.exit(1);
  }
}

runCard5Tests();
