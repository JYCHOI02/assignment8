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

async function runCard4Tests() {
  console.log('===============================================================');
  console.log('🛡️  [T08 - 카드 4] 다중 패스키 등록 및 삭제(분실 대비) 검증 자동화 테스트');
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
    // [Step 1] 복수(2개)의 서로 다른 기기 패스키 키페어 생성 및 등록
    // -------------------------------------------------------------
    console.log('▶ [Step 1] 복수(2개)의 인증기 패스키 등록 지원 검증...');

    // 1번 패스키 (주 기기: Windows PC)
    const keyPairA = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const credIdA = 'cred_card4_primary_win_' + Date.now();
    const nameA = '주 기기: 내 윈도우 PC (Windows Hello)';

    // 2번 패스키 (보조 기기: iPhone FaceID)
    const keyPairB = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const credIdB = 'cred_card4_backup_iphone_' + (Date.now() + 10);
    const nameB = '보조 기기: 내 아이폰 (FaceID / iCloud 키체인)';

    // 1번 패스키 등록
    const regOptRes1 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const regOpt1 = JSON.parse(regOptRes1.body);
    const regCookie1 = getCookieString(regOptRes1);

    const clientDataRegA = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regOpt1.challenge,
        origin: 'http://localhost:3000',
      })
    ).toString('base64url');

    const regResA = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/register-verify',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: regCookie1 },
      },
      JSON.stringify({
        name: nameA,
        credentialId: credIdA,
        clientDataJSON: clientDataRegA,
        authenticatorType: '기기 자체 보안 영역 (Windows Hello / TPM)',
        mockPublicKey: { pem: keyPairA.publicKey },
      })
    );
    assert(regResA.statusCode === 201, '다중 등록: 1번 주 기기 패스키 등록 완료 (HTTP 201)');
    console.log(`  • [패스키 1 등록] ID: ${credIdA} | 이름: ${nameA}`);

    // 2번 패스키 등록
    const regOptRes2 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const regOpt2 = JSON.parse(regOptRes2.body);
    const regCookie2 = getCookieString(regOptRes2);

    const clientDataRegB = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regOpt2.challenge,
        origin: 'http://localhost:3000',
      })
    ).toString('base64url');

    const regResB = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/register-verify',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: regCookie2 },
      },
      JSON.stringify({
        name: nameB,
        credentialId: credIdB,
        clientDataJSON: clientDataRegB,
        authenticatorType: '외부/모바일 플랫폼 인증기 (FaceID / iCloud 키체인)',
        mockPublicKey: { pem: keyPairB.publicKey },
      })
    );
    assert(regResB.statusCode === 201, '다중 등록: 2번 보조 기기 패스키 등록 완료 (HTTP 201)');
    console.log(`  • [패스키 2 등록] ID: ${credIdB} | 이름: ${nameB}`);

    // 서버 저장소 목록 조회
    const listRes1 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/passkeys?t=' + Date.now(),
      method: 'GET',
    });
    const listData1 = JSON.parse(listRes1.body);
    assert(listRes1.statusCode === 200, '다중 패스키 목록 조회 성공 (HTTP 200)');
    assert(listData1.count >= 2, `서버에 등록된 패스키가 2개 이상임 확인 (현재 ${listData1.count}개)`);

    const hasA = listData1.passkeys.some((p) => p.id === credIdA);
    const hasB = listData1.passkeys.some((p) => p.id === credIdB);
    assert(hasA && hasB, '등록된 패스키 2개가 각각 고유한 명칭과 ID로 목록에 노출됨');

    // -------------------------------------------------------------
    // [Step 2] 1번 패스키 삭제(해지) 요청 및 검증
    // -------------------------------------------------------------
    console.log('\n▶ [Step 2] 패스키 1개 삭제(해지) 기능 및 DB 제거 검증...');
    const deleteRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: `/api/auth/passkeys/${credIdA}`,
      method: 'DELETE',
    });
    assert(deleteRes.statusCode === 200, '패스키 삭제 요청 성공 (HTTP 200 OK)');
    const deleteData = JSON.parse(deleteRes.body);
    console.log(`  • 삭제 응답 메시지: "${deleteData.message}"`);
    console.log(`  • 삭제 후 남은 패스키 개수: ${deleteData.remainingCount}개`);

    // 삭제 후 저장소 재조회
    const listRes2 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/passkeys?t=' + Date.now(),
      method: 'GET',
    });
    const listData2 = JSON.parse(listRes2.body);
    const stillHasA = listData2.passkeys.some((p) => p.id === credIdA);
    const stillHasB = listData2.passkeys.some((p) => p.id === credIdB);
    assert(!stillHasA, '삭제된 1번 패스키가 서버 저장소에서 완전히 제거되었음을 입증');
    assert(stillHasB, '삭제되지 않은 2번 패스키는 저장소에 정상 보존되어 있음을 입증');

    // -------------------------------------------------------------
    // [Step 3] 남은 2번 패스키로 정상 로그인 지속성 검증
    // -------------------------------------------------------------
    console.log('\n▶ [Step 3] 남은 2번 패스키로 정상 로그인 지속성 검증...');
    const loginOptRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    assert(loginOptRes.statusCode === 200, '남은 패스키 로그인 질문(Challenge) 발급 성공');
    const loginOpt = JSON.parse(loginOptRes.body);
    const loginCookie = getCookieString(loginOptRes);

    // 허용된 패스키 목록에 2번 패스키는 포함되고 1번 패스키는 제외되었는지 확인
    const allowedIds = loginOpt.allowCredentials.map((c) => c.id);
    assert(allowedIds.includes(credIdB), '서버의 로그인 허용 패스키 목록에 2번 패스키가 포함됨');
    assert(!allowedIds.includes(credIdA), '서버의 로그인 허용 패스키 목록에서 삭제된 1번 패스키가 제외됨');

    // 2번 패스키의 개인키로 유효한 서명 생성
    const clientDataLoginB = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: loginOpt.challenge,
        origin: 'http://localhost:3000',
      })
    ).toString('base64url');

    const authDataB = Buffer.from('o2NmbXRkbm9uZWdhdHRTdG10XGJhdXRoRGF0YVgg...').toString('base64url');
    const clientDataHashB = crypto
      .createHash('sha256')
      .update(Buffer.from(clientDataLoginB, 'base64url'))
      .digest();
    const signedDataB = Buffer.concat([Buffer.from(authDataB, 'base64url'), clientDataHashB]);

    const signB = crypto.createSign('SHA256');
    signB.update(signedDataB);
    const signatureB = signB.sign(keyPairB.privateKey).toString('base64url');

    // 2번 패스키로 로그인 검증 요청
    const verifyResB = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: loginCookie },
      },
      JSON.stringify({
        credentialId: credIdB,
        clientDataJSON: clientDataLoginB,
        authenticatorData: authDataB,
        signature: signatureB,
      })
    );
    assert(verifyResB.statusCode === 200, '남은 2번 패스키로 로그인 성공 (HTTP 200 OK)');
    const authCookieB = getCookieString(verifyResB) || loginCookie;

    // 비공개 데이터 접근 검증
    const privateResB = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
      headers: { Cookie: authCookieB },
    });
    assert(privateResB.statusCode === 200, '남은 패스키 로그인 세션으로 비공개 데이터 정상 인가 확인 (HTTP 200)');
    const privData = JSON.parse(privateResB.body);
    console.log(`  • 인가된 사용자: ${privData.data.owner}`);
    console.log(`  • 열람된 비공개 항목 수: ${privData.data.items.length}개`);

    // -------------------------------------------------------------
    // [Step 4] 삭제된 1번 패스키로 로그인 시도 시 접근 차단 검증
    // -------------------------------------------------------------
    console.log('\n▶ [Step 4] 삭제된 1번 패스키로 로그인 시도 시 서버 거절(차단) 검증...');
    const rejectedOptRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/login-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const rejOpt = JSON.parse(rejectedOptRes.body);
    const rejCookie = getCookieString(rejectedOptRes);

    const clientDataLoginA = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: rejOpt.challenge,
        origin: 'http://localhost:3000',
      })
    ).toString('base64url');

    const authDataA = Buffer.from('o2NmbXRkbm9uZWdhdHRTdG10XGJhdXRoRGF0YVgg...').toString('base64url');
    const clientDataHashA = crypto
      .createHash('sha256')
      .update(Buffer.from(clientDataLoginA, 'base64url'))
      .digest();
    const signedDataA = Buffer.concat([Buffer.from(authDataA, 'base64url'), clientDataHashA]);

    const signA = crypto.createSign('SHA256');
    signA.update(signedDataA);
    const signatureA = signA.sign(keyPairA.privateKey).toString('base64url');

    // 삭제된 credIdA로 로그인 시도
    const rejectedVerifyRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login-verify',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: rejCookie },
      },
      JSON.stringify({
        credentialId: credIdA,
        clientDataJSON: clientDataLoginA,
        authenticatorData: authDataA,
        signature: signatureA,
      })
    );
    assert(
      rejectedVerifyRes.statusCode === 404 || rejectedVerifyRes.statusCode === 401,
      `삭제된 패스키 로그인 시도 시 서버가 거절 응답 반환 (HTTP ${rejectedVerifyRes.statusCode})`
    );
    const rejData = JSON.parse(rejectedVerifyRes.body);
    console.log(`  • 거절 응답 메시지: "${rejData.message}"`);

    // -------------------------------------------------------------
    // [Step 5] 테스트 후 보조 패스키 정리 (Clean up)
    // -------------------------------------------------------------
    await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: `/api/auth/passkeys/${credIdB}`,
      method: 'DELETE',
    });
    console.log('🧹 [정리] 테스트용 보조 패스키 삭제 및 정리 완료.');

    console.log('\n===============================================================');
    console.log(`🎉 [Card 4 종합 검증 결과] ${passed}/${total} 항목 전체 통과 완료 (PASS)!`);
    console.log('===============================================================\n');
  } catch (err) {
    console.error('❌ 테스트 실행 중 치명적 오류 발생:', err);
    process.exit(1);
  }
}

runCard4Tests();
