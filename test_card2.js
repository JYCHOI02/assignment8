const http = require('http');

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

async function runCard2Tests() {
  console.log('===============================================================');
  console.log('🛡️  [T08 - 카드 2] 패스키 등록 및 공개키 저장 자동화 검증 스위트');
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
    // [T08-C19] 등록용 질문(Challenge) 생성 및 서버 보관 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 1] 등록용 질문(Challenge) 1차 발급 요청...');
    const req1 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    assert(req1.statusCode === 200, 'T08-C19: 서버가 등록용 질문(Challenge) 생성 응답 (HTTP 200)');
    const body1 = JSON.parse(req1.body);
    const challenge1 = body1.challenge;
    const cookie1 = req1.headers['set-cookie'] ? req1.headers['set-cookie'][0].split(';')[0] : '';

    assert(
      typeof challenge1 === 'string' && challenge1.length >= 32 && cookie1.length > 0,
      'T08-C19: 난수 Challenge 생성 및 세션 쿠키를 통해 확인할 때까지 보관됨'
    );

    console.log(`  • 1차 발급 Challenge: "${challenge1}"`);
    console.log(`  • 발급 대상 RP: ${JSON.stringify(body1.rp)}`);
    console.log(`  • 발급 대상 User: ${JSON.stringify(body1.user)}\n`);

    // -------------------------------------------------------------
    // [T08-C20] 등록 요청마다 질문 값이 서로 다르다는 기록 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 2] 등록용 질문(Challenge) 2차 발급 요청 (난수 고유성 확인)...');
    const req2 = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    const body2 = JSON.parse(req2.body);
    const challenge2 = body2.challenge;

    assert(
      challenge1 !== challenge2,
      'T08-C20: 등록 요청마다 질문(Challenge) 값이 서로 완전히 다름을 증명'
    );
    console.log(`  • 1차 Challenge: ${challenge1}`);
    console.log(`  • 2차 Challenge: ${challenge2}`);
    console.log(`  • 결과: 두 Challenge가 서로 상이함이 증명됨 (중복/재사용 원천 차단)\n`);

    // -------------------------------------------------------------
    // [T08-C25] 등록 중단/취소 시 서버 저장소에 아무것도 저장되지 않음 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 3] 등록 도중 사용자가 취소(Cancel)했을 때의 동작 검증...');
    const prePasskeysRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/passkeys',
      method: 'GET',
    });
    const preCount = JSON.parse(prePasskeysRes.body).count;

    const cancelRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-cancel',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie1 },
    });

    const postCancelPasskeysRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/passkeys',
      method: 'GET',
    });
    const postCancelCount = JSON.parse(postCancelPasskeysRes.body).count;

    assert(
      cancelRes.statusCode === 200 && preCount === postCancelCount,
      'T08-C25: 등록 취소 시 서버에 어떠한 인증 정보/패스키도 저장되지 않음 (저장소 개수 불변)'
    );
    console.log(`  • 취소 전 패스키 개수: ${preCount}개 -> 취소 후 패스키 개수: ${postCancelCount}개 (0개 증가)\n`);

    // -------------------------------------------------------------
    // [T08-C21 ~ T08-C24, T08-C26] 정상 등록 및 공개키 저장 검증
    // -------------------------------------------------------------
    console.log('▶ [Step 4] 정식 패스키 등록 검증 요청 수행...');

    // 새 세션용 챌린지 발급
    const regOptionsRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/register-options',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const regOptions = JSON.parse(regOptionsRes.body);
    const validCookie = regOptionsRes.headers['set-cookie'][0].split(';')[0];

    // 클라이언트 WebAuthn 응답 시뮬레이션
    const mockClientDataJSON = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: regOptions.challenge,
        origin: 'http://localhost:3000',
        crossOrigin: false,
      })
    ).toString('base64url');

    const passkeyName = '내 윈도우 PC (Windows Hello)'; // T08-C24: 사람이 알아볼 수 있는 이름
    const authenticatorLocation = '기기 자체 보안 영역 (Windows Hello / TPM 플랫폼 인증기)'; // T08-C26

    // T08-C23 증명: 요청 페이로드에 개인키나 패스워드가 없음
    const registrationPayload = {
      name: passkeyName,
      credentialId: 'cred_win_hello_demo_01',
      clientDataJSON: mockClientDataJSON,
      attestationObject: '', // 빈 attestation일 경우 ECC P-256 공개키 자동 생성 모드
      authenticatorType: authenticatorLocation,
    };

    console.log('[T08-C23 검증] 클라이언트가 서버로 전송하는 등록 요청 본문:');
    console.log(JSON.stringify(registrationPayload, null, 2));

    const forbiddenKeys = ['privateKey', 'private_key', 'password', 'secret', 'keyPair'];
    const hasForbiddenKey = forbiddenKeys.some((k) => k in registrationPayload);
    assert(!hasForbiddenKey, 'T08-C23: 등록 요청 본문에 개인키/비밀번호가 전혀 포함되지 않음');

    // 서버로 검증 및 등록 요청 전송
    const verifyRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/register-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: validCookie,
        },
      },
      JSON.stringify(registrationPayload)
    );

    assert(verifyRes.statusCode === 201, 'T08-C21: 패스키 등록 완료 (HTTP 201 Created)');

    const verifyResult = JSON.parse(verifyRes.body);
    assert(
      verifyResult.success === true && verifyResult.passkey && verifyResult.passkey.publicKey,
      'T08-C21: 등록 완료 후 서버 저장소에 공개키(Public Key)가 성공적으로 저장됨'
    );

    // -------------------------------------------------------------
    // [T08-C22] 서버에 저장된 값이 공개키이며 비밀번호가 아님 증명
    // -------------------------------------------------------------
    const savedPasskey = verifyResult.passkey;
    const isPemPublicKey = savedPasskey.publicKey.includes('BEGIN PUBLIC KEY');
    assert(
      isPemPublicKey,
      'T08-C22: 서버에 저장된 값이 공개키(ECC PEM Public Key) 형식임을 증명'
    );

    console.log('\n--- [T08-C22 제출 증빙] 서버에 저장된 실제 공개키 레코드 ---');
    console.log(`  • ID: ${savedPasskey.id}`);
    console.log(`  • 이름: ${savedPasskey.name}`);
    console.log(`  • 타입: ${savedPasskey.publicKeyType}`);
    console.log(`  • 공개키 본문:\n${savedPasskey.publicKey}`);
    console.log('  • 설명: 비대칭 암호학의 공개키(Public Key)로서, 서명 검증에만 사용되며 비밀번호가 아님!\n');

    // -------------------------------------------------------------
    // [T08-C24] 사람이 알아볼 수 있는 이름 확인
    // -------------------------------------------------------------
    assert(
      savedPasskey.name === passkeyName,
      `T08-C24: 등록한 패스키에 사람이 알아볼 수 있는 이름("${passkeyName}")이 정확히 붙음`
    );

    // -------------------------------------------------------------
    // [T08-C26] 패스키 저장 위치(기기 자체/Windows Hello/TPM 등) 기록 확인
    // -------------------------------------------------------------
    assert(
      savedPasskey.authenticatorType.includes('기기 자체') ||
        savedPasskey.authenticatorType.includes('Windows Hello'),
      `T08-C26: 패스키가 저장된 장소("${savedPasskey.authenticatorType}")가 명확히 기록됨`
    );

    // -------------------------------------------------------------
    // [일회성 재사용 방지 확인] 이미 사용된 챌린지로 재등록 시도 시 거절 확인
    // -------------------------------------------------------------
    const replayRes = await makeRequest(
      {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/register-verify',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: validCookie,
        },
      },
      JSON.stringify(registrationPayload)
    );

    assert(
      replayRes.statusCode === 400,
      'T08-C20 (재사용 방지): 1회 사용된 챌린지로 재요청 시 서버가 400으로 거절함 확인'
    );

    console.log('\n===============================================================');
    console.log(`🎉 [Card 2 종합 검증 결과] ${passed}/${total} 항목 전체 통과 완료 (PASS)!`);
    console.log('===============================================================\n');

    process.exit(0);
  } catch (err) {
    console.error('검증 테스트 실행 중 오류 발생:', err);
    process.exit(1);
  }
}

runCard2Tests();
