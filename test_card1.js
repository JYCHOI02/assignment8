const http = require('http');

// Simple test runner for Card 1 requirements
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

async function runTests() {
  console.log('🔍 [Card 1 Verification Test Suite Starting]...\n');
  let passedCount = 0;
  let totalCount = 0;

  function assert(condition, testName, details = '') {
    totalCount++;
    if (condition) {
      console.log(`✅ PASS: ${testName}`);
      passedCount++;
    } else {
      console.error(`❌ FAIL: ${testName} - ${details}`);
    }
  }

  try {
    // Test 1: T08-C16 & T08-C17 - Direct unauthenticated call to /api/private-data returns 401
    const unauthRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
    });

    assert(
      unauthRes.statusCode === 401,
      'T08-C17: 미인증 요청에 대해 HTTP 401 Unauthorized 반환',
      `Expected 401, got ${unauthRes.statusCode}`
    );

    const unauthBody = JSON.parse(unauthRes.body);
    assert(
      unauthBody.success === false && !unauthBody.data,
      'T08-C16: 미인증 상태에서 비공개 API 거절 및 데이터 미반환',
      `Body contains data: ${!!unauthBody.data}`
    );

    // Test 2: T08-C18 - Initial HTML does NOT contain private secret text
    const htmlRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/',
      method: 'GET',
    });

    const forbiddenTexts = [
      'AgentShield',
      '알파 시큐리티',
      '준비 중인 사이드 프로젝트 아이디어 노트',
      '지원 희망 기업 및 포지션 스크랩 목록',
      '월간 학습 및 역량 개발 자체 회고록',
    ];

    let leakFound = false;
    let leakedText = '';
    for (const text of forbiddenTexts) {
      if (htmlRes.body.includes(text)) {
        leakFound = true;
        leakedText = text;
        break;
      }
    }

    assert(
      !leakFound,
      'T08-C18: 초기 HTML 소스 코드에 비공개 텍스트 노출 차단',
      `Found leaked text in HTML: "${leakedText}"`
    );

    assert(
      htmlRes.body.includes('id="privateDashboard"') &&
        htmlRes.body.includes('패스키 인증이 필요한 비공개 영역입니다'),
      'T08-C13 & T08-C15: 비공개 영역 UI 컨테이너 및 미로그인 잠금 안내 문구 확인'
    );

    // Test 3: Authenticated session flow (Mock Login -> Get Private Data)
    const loginRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/mock-login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    const cookie = loginRes.headers['set-cookie']
      ? loginRes.headers['set-cookie'][0].split(';')[0]
      : '';

    assert(
      loginRes.statusCode === 200 && cookie.length > 0,
      'Card 1 인증 세션 정상 발급',
      `Status: ${loginRes.statusCode}`
    );

    // Test 4: T08-C14 - 3 or more private items returned when authenticated
    const authRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
      headers: { Cookie: cookie },
    });

    assert(
      authRes.statusCode === 200,
      '인가된 세션으로 /api/private-data 호출 시 HTTP 200 반환',
      `Got ${authRes.statusCode}`
    );

    const authBody = JSON.parse(authRes.body);
    const items = authBody.data && authBody.data.items;
    assert(
      Array.isArray(items) && items.length >= 3,
      'T08-C14: 비공개 영역에 들어갈 가상 항목 3개 이상 정의 및 반환 확인',
      `Items count: ${items ? items.length : 0}`
    );

    console.log('\n--- 인가 시 반환된 비공개 항목 목록 ---');
    items.forEach((item, idx) => {
      console.log(`  [항목 ${idx + 1}] ${item.title} (${item.badge})`);
    });

    // Test 5: Logout and verify re-lock
    const logoutRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/auth/logout',
      method: 'POST',
      headers: { Cookie: cookie },
    });

    const postLogoutRes = await makeRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/api/private-data',
      method: 'GET',
      headers: { Cookie: cookie },
    });

    assert(
      postLogoutRes.statusCode === 401,
      '로그아웃 후 즉시 비공개 API 접근 차단 (401 반환) 확인'
    );

    console.log(`\n========================================`);
    console.log(`🎉 검증 결과: ${passedCount}/${totalCount} 테스트 통과 완료!`);
    console.log(`========================================\n`);

    if (passedCount === totalCount) {
      process.exit(0);
    } else {
      process.exit(1);
    }
  } catch (err) {
    console.error('Test execution error:', err);
    process.exit(1);
  }
}

runTests();
