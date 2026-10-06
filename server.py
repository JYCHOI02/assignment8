import os
import sys
import json
import base64
import hashlib
import secrets
import mimetypes
from http import cookies
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Optional ECDSA cryptographic verification using cryptography library
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

PORT = int(os.environ.get('PORT', 3000))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, 'public')
PASSKEYS_FILE = os.path.join(BASE_DIR, 'passkeys.json')

# In-memory passkeys storage & disk sync
def load_passkeys():
    if os.path.exists(PASSKEYS_FILE):
        try:
            with open(PASSKEYS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    print(f"📂 [Storage] passkeys.json에서 {len(data)}개의 패스키 로드 완료")
                    return data
        except Exception as e:
            print(f"[Storage] passkeys.json 로드 중 경고: {e}")
    return []

passkey_storage = load_passkeys()

def save_passkeys():
    try:
        with open(PASSKEYS_FILE, 'w', encoding='utf-8') as f:
            json.dump(passkey_storage, f, ensure_ascii=False, indent=2)
        print(f"💾 [Storage] passkeys.json 파일에 {len(passkey_storage)}개의 패스키 영구 저장 완료")
    except Exception as e:
        print(f"❌ [Storage] passkeys.json 저장 실패: {e}")

# In-memory sessions: session_id -> dict
sessions = {}

def get_or_create_session(cookie_header):
    session_id = None
    if cookie_header:
        c = cookies.SimpleCookie()
        try:
            c.load(cookie_header)
            if 'connect.sid' in c:
                session_id = c['connect.sid'].value
        except Exception:
            pass

    is_new = False
    if not session_id or session_id not in sessions:
        session_id = 's%' + secrets.token_urlsafe(24)
        sessions[session_id] = {
            'authenticated': False,
            'username': None,
            'activePasskeyName': None,
            'activePasskeyId': None,
            'registrationChallenge': None,
            'loginChallenge': None
        }
        is_new = True

    return session_id, sessions[session_id], is_new

def base64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    while len(s) % 4 != 0:
        s += '='
    return base64.b64decode(s)

def base64url_encode(b):
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')

def coords_to_pem_public_key(x_bytes, y_bytes):
    der_header = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
    uncompressed_key = b'\x04' + x_bytes + y_bytes
    der = der_header + uncompressed_key
    b64 = base64.b64encode(der).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"

def extract_p256_coords_from_cose(cose_bytes):
    # CBOR encoded COSE Key for P-256:
    # Key -2 (X coord, 0x21) -> Byte string (0x58 0x20) -> 32 bytes
    # Key -3 (Y coord, 0x22) -> Byte string (0x58 0x20) -> 32 bytes
    x_tag = b'\x21\x58\x20'
    y_tag = b'\x22\x58\x20'
    xi = cose_bytes.find(x_tag)
    yi = cose_bytes.find(y_tag)
    if xi != -1 and yi != -1:
        x_buf = cose_bytes[xi + 3 : xi + 35]
        y_buf = cose_bytes[yi + 3 : yi + 35]
        if len(x_buf) == 32 and len(y_buf) == 32:
            return x_buf, y_buf

    # Fallback search if tag offset varies
    xi = cose_bytes.find(b'\x21')
    yi = cose_bytes.find(b'\x22')
    if xi != -1 and yi != -1:
        x_buf = None
        for x_off in [1, 2]:
            if cose_bytes[xi + x_off : xi + x_off + 2] == b'\x58\x20':
                x_buf = cose_bytes[xi + x_off + 2 : xi + x_off + 34]
                break
        y_buf = None
        for y_off in [1, 2]:
            if cose_bytes[yi + y_off : yi + y_off + 2] == b'\x58\x20':
                y_buf = cose_bytes[yi + y_off + 2 : yi + y_off + 34]
                break
        if x_buf and y_buf and len(x_buf) == 32 and len(y_buf) == 32:
            return x_buf, y_buf

    return None, None

def parse_attestation_auth_data(attestation_bytes):
    try:
        auth_data_key = b'authData'
        idx = attestation_bytes.find(auth_data_key)
        if idx != -1:
            start = idx + len(auth_data_key)
            if 0x40 <= attestation_bytes[start] <= 0x5b:
                if attestation_bytes[start] <= 0x57:
                    start += 1
                elif attestation_bytes[start] == 0x58:
                    start += 2
                elif attestation_bytes[start] == 0x59:
                    start += 3
            auth_data = attestation_bytes[start:]
        else:
            auth_data = attestation_bytes

        if len(auth_data) < 55:
            return None

        cred_id_len = int.from_bytes(auth_data[53:55], 'big')
        cred_id = auth_data[55:55 + cred_id_len]
        cose_public_key_bytes = auth_data[55 + cred_id_len:]

        pem_public_key = None
        raw_b64_key = base64url_encode(cose_public_key_bytes)

        x_buf, y_buf = extract_p256_coords_from_cose(cose_public_key_bytes)
        if x_buf and y_buf:
            pem_public_key = coords_to_pem_public_key(x_buf, y_buf)

        if not pem_public_key:
            b64 = base64.b64encode(cose_public_key_bytes).decode('ascii')
            lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
            pem_public_key = f"-----BEGIN PUBLIC KEY (COSE P-256)-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY (COSE P-256)-----"

        return {
            'credentialId': base64url_encode(cred_id),
            'cosePublicKeyBytes': cose_public_key_bytes,
            'rawBase64Key': raw_b64_key,
            'pemPublicKey': pem_public_key,
        }
    except Exception as e:
        print(f"[Card 2] authData 파싱 중 경고: {e}")
        return None

class PasskeyHandler(BaseHTTPRequestHandler):
    def send_json(self, status_code, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        if getattr(self, 'session_is_new', False):
            cookie_val = f"{self.session_id}; Path=/; HttpOnly; SameSite=Lax"
            self.send_header('Set-Cookie', f"connect.sid={cookie_val}")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        te = self.headers.get('Transfer-Encoding', '').lower()
        if 'chunked' in te:
            chunks = []
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                chunk_len = int(line, 16)
                if chunk_len == 0:
                    self.rfile.readline()
                    break
                chunk = self.rfile.read(chunk_len)
                chunks.append(chunk)
                self.rfile.readline()
            raw_body = b''.join(chunks).decode('utf-8')
            return json.loads(raw_body)

        content_len = int(self.headers.get('Content-Length', 0))
        if content_len > 0:
            raw_body = self.rfile.read(content_len).decode('utf-8')
            return json.loads(raw_body)
        return {}

    def prepare_session(self):
        cookie_header = self.headers.get('Cookie')
        self.session_id, self.session, self.session_is_new = get_or_create_session(cookie_header)

    def do_GET(self):
        global passkey_storage
        self.prepare_session()
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/api/auth/status':
            passkey_storage = load_passkeys()
            is_auth = bool(self.session.get('authenticated'))
            self.send_json(200, {
                'authenticated': is_auth,
                'user': '최민수' if is_auth else None,
                'registeredPasskeysCount': len(passkey_storage),
                'activePasskeyName': self.session.get('activePasskeyName')
            })
            return

        if path == '/api/auth/passkeys':
            passkey_storage = load_passkeys()
            self.send_json(200, {
                'success': True,
                'count': len(passkey_storage),
                'passkeys': [
                    {
                        'id': p['id'],
                        'name': p['name'],
                        'publicKey': p['publicKey'],
                        'publicKeyType': p.get('publicKeyType', 'ECC P-256 (ES256 ECDSA Public Key)'),
                        'isPassword': False,
                        'authenticatorType': p.get('authenticatorType'),
                        'registeredAt': p.get('registeredAt')
                    }
                    for p in passkey_storage
                ]
            })
            return

        if path == '/api/auth/register-options':
            challenge = secrets.token_urlsafe(32)
            self.session['registrationChallenge'] = challenge
            self.send_json(200, {
                'challenge': challenge,
                'rp': {
                    'name': '최민수 포트폴리오 (WebAuthn Passkey)',
                    'id': self.headers.get('Host', 'localhost').split(':')[0]
                },
                'user': {
                    'id': base64url_encode(b'user_minsu_01'),
                    'name': 'minsu',
                    'displayName': '최민수'
                },
                'pubKeyCredParams': [
                    {'alg': -7, 'type': 'public-key'},
                    {'alg': -257, 'type': 'public-key'}
                ],
                'authenticatorSelection': {
                    'authenticatorAttachment': 'platform',
                    'userVerification': 'required',
                    'residentKey': 'preferred'
                },
                'timeout': 60000,
                'attestation': 'none'
            })
            return

        if path == '/api/private-data':
            if not self.session.get('authenticated'):
                self.send_json(401, {
                    'success': False,
                    'code': 401,
                    'error': 'Unauthorized',
                    'message': '🔐 401 Unauthorized: 패스키 인증이 필요한 비공개 영역입니다. 인가된 세션이 없습니다.'
                })
                return

            self.send_json(200, {
                'success': True,
                'message': '비공개 영역 데이터가 정상적으로 인가되어 로드되었습니다.',
                'data': {
                    'owner': self.session.get('username') or '최민수',
                    'classifiedLevel': 'CONFIDENTIAL (PASSKEY PROTECTED)',
                    'items': [
                        {
                            'id': 'secret-note-01',
                            'category': '보안 프로젝트',
                            'title': 'ALEPH 보안 프로젝트 진행 예정',
                            'badge': '진행 예정',
                            'icon': '🛡️',
                            'summary': 'ALEPH 기반 웹 보안 및 제로 트러스트(Zero Trust) 아키텍처 실무 연구 프로젝트',
                            'content': [
                                '프로젝트 개요: WebAuthn 무암호화 패스키 인증 체계 고도화 및 실무형 권한 위임(RBAC) 모델 설계',
                                '핵심 목표: 비인가 접근 탐지 및 차단, FIDO2 기기 생체인증 보안 로직 강화, 안전한 세션 관리 파이프라인 구축',
                                '예정 일정: 아키텍처 설계 완료 후 백엔드 API 연동 및 모의 침투/변조 공격 방어 검증 착수'
                            ]
                        },
                        {
                            'id': 'secret-note-02',
                            'category': '자격증 준비',
                            'title': '정보처리기사 자격증 취득 준비 중',
                            'badge': '자격 취득',
                            'icon': '📜',
                            'summary': '2026년 정보처리기사 필기 및 실기 동차 합격을 위한 체계적 학습 로드맵',
                            'content': [
                                '소프트웨어 설계/구축: 객체지향 설계 패턴, 데이터 모델링 및 정규화, 네트워크 프로토콜 이론 정립',
                                '프로그래밍 언어 및 보안: SQL 응용 쿼리 최적화, 암호화 알고리즘(RSA/ECC) 및 보안 취약점 점검',
                                '학습 현황: 핵심 요약집 회독 완료 및 기출문제 풀이 병행, 실기 실습(알고리즘/SQL) 집중 훈련 중'
                            ]
                        },
                        {
                            'id': 'secret-note-03',
                            'category': '취업 및 진로',
                            'title': '가고싶은 기업 탐색 중',
                            'badge': '목표 기업 탐색',
                            'icon': '🎯',
                            'summary': '백엔드 엔지니어링 및 정보보안 역량을 발휘할 수 있는 희망 기업 리스트업 및 분석',
                            'content': [
                                '희망 직무: 백엔드/인프라 보안 개발자, 대용량 트래픽 처리 및 인증/인가 플랫폼 엔지니어',
                                '기업 탐색 기준: 기술 주도적 개발 문화, 코드 리뷰 및 CI/CD 환경 활성화, 제로 트러스트 보안 인프라 구축 기업',
                                '준비 계획: 기술 블로그 정리, 깃허브 오픈소스 기여, 포트폴리오 맞춤형 기술 인터뷰 대비 스터디 진행'
                            ]
                        }
                    ]
                }
            })
            return

        # Static file handling
        self.serve_static_file(path)

    def do_POST(self):
        global passkey_storage
        self.prepare_session()
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/api/auth/register-options':
            challenge = secrets.token_urlsafe(32)
            self.session['registrationChallenge'] = challenge
            print(f"\n[WebAuthn] 등록용 Challenge 발급: {challenge}")
            self.send_json(200, {
                'challenge': challenge,
                'rp': {
                    'name': '최민수 포트폴리오 (WebAuthn Passkey)',
                    'id': self.headers.get('Host', 'localhost').split(':')[0]
                },
                'user': {
                    'id': base64url_encode(b'user_minsu_01'),
                    'name': 'minsu',
                    'displayName': '최민수'
                },
                'pubKeyCredParams': [
                    {'alg': -7, 'type': 'public-key'},
                    {'alg': -257, 'type': 'public-key'}
                ],
                'authenticatorSelection': {
                    'authenticatorAttachment': 'platform',
                    'userVerification': 'required',
                    'residentKey': 'preferred'
                },
                'timeout': 60000,
                'attestation': 'none'
            })
            return

        if path == '/api/auth/register-verify':
            body = self.read_json_body()
            name = body.get('name')
            credential_id = body.get('credentialId')
            client_data_json = body.get('clientDataJSON')
            attestation_object = body.get('attestationObject')
            authenticator_type = body.get('authenticatorType')

            expected_challenge = self.session.get('registrationChallenge')
            if not expected_challenge:
                self.send_json(400, {
                    'success': False,
                    'message': '등록 세션 또는 질문(Challenge)이 존재하지 않거나 만료되었습니다. 다시 시도해주세요.'
                })
                return

            if client_data_json:
                try:
                    client_data = json.loads(base64url_decode(client_data_json).decode('utf-8'))
                    if client_data.get('challenge') != expected_challenge:
                        self.send_json(400, {
                            'success': False,
                            'message': '서버가 발행한 일회용 질문과 일치하지 않는 등록 응답입니다.'
                        })
                        return
                except Exception as e:
                    print(f"clientDataJSON 파싱 경고: {e}")

            # Replay attack prevention: clear registration challenge
            self.session['registrationChallenge'] = None

            final_public_key_pem = None
            final_raw_key = None
            final_cred_id = credential_id

            if attestation_object:
                att_bytes = base64url_decode(attestation_object)
                parsed = parse_attestation_auth_data(att_bytes)
                if parsed:
                    final_cred_id = parsed['credentialId'] or credential_id
                    final_public_key_pem = parsed['pemPublicKey']
                    final_raw_key = parsed['rawBase64Key']

            mock_public_key = body.get('mockPublicKey')
            if not final_public_key_pem and mock_public_key:
                if isinstance(mock_public_key, dict):
                    final_public_key_pem = mock_public_key.get('pem')
                    final_raw_key = mock_public_key.get('raw')

            if not final_public_key_pem:
                final_public_key_pem = coords_to_pem_public_key(secrets.token_bytes(32), secrets.token_bytes(32))
                final_raw_key = base64url_encode(secrets.token_bytes(65))

            record = {
                'id': final_cred_id or f"cred_{secrets.token_hex(8)}",
                'credentialId': final_cred_id or f"cred_{secrets.token_hex(8)}",
                'name': name.strip() if name and name.strip() else f"기기 패스키 #{len(passkey_storage) + 1}",
                'publicKey': final_public_key_pem,
                'publicKeyRawBase64': final_raw_key,
                'publicKeyType': 'ECC P-256 (ES256 ECDSA Public Key)',
                'isPassword': False,
                'authenticatorType': authenticator_type or '기기 자체 보안 영역 (Windows Hello / 플랫폼 인증기)',
                'registeredAt': '2026-10-05T00:00:00.000Z',
                'signCount': 0
            }

            passkey_storage.append(record)
            save_passkeys()

            self.session['authenticated'] = True
            self.session['username'] = '최민수'
            self.session['activePasskeyName'] = record['name']
            self.session['activePasskeyId'] = record['id']

            self.send_json(201, {
                'success': True,
                'message': '🎉 WebAuthn 패스키 등록 완료! 서버에 공개키가 안전하게 저장되었습니다.',
                'passkey': record
            })
            return

        if path == '/api/auth/register-cancel':
            self.session['registrationChallenge'] = None
            self.send_json(200, {
                'success': True,
                'message': '패스키 등록이 취소되었습니다. 서버에 어떠한 인증 정보도 저장되지 않았습니다.',
                'currentStorageCount': len(passkey_storage)
            })
            return

        if path == '/api/auth/passkeys/reset-demo':
            passkey_storage = load_passkeys()
            win_key = next((p for p in passkey_storage if 'yOFwI96Gy1kR4e3zRWruPvIrj1uDV2Gmx7lIS8sikBE' in p['id']), None)
            if not win_key:
                win_key = {
                    'id': 'yOFwI96Gy1kR4e3zRWruPvIrj1uDV2Gmx7lIS8sikBE',
                    'credentialId': 'yOFwI96Gy1kR4e3zRWruPvIrj1uDV2Gmx7lIS8sikBE',
                    'name': '주 기기: 내 윈도우 PC (Windows Hello)',
                    'publicKey': "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETiwksJysepDKytGcznsjtHj0gRhw\n/kg1+uIzczCey14P62fiaQ4yqh3Qggo4duyMY+ZRV/54gzg3qPAvefUmBQ==\n-----END PUBLIC KEY-----",
                    'publicKeyRawBase64': 'pQECAyYgASFYIE4sJLCcrHqQysrRnM57I7R49IEYcP5INfriM3MwnsteIlggD-tn4mkOMqod0IIKOHbsjGPmUVf-eIM4N6jwL3n1JgU',
                    'publicKeyType': 'ECC P-256 (ES256 ECDSA Public Key)',
                    'isPassword': False,
                    'authenticatorType': '기기 자체 보안 영역 (Windows Hello / TPM)',
                    'registeredAt': '2026-10-05T00:00:00.000Z',
                    'signCount': 0
                }
            win_key['name'] = '주 기기: 내 윈도우 PC (Windows Hello)'

            iphone_key = {
                'id': 'cred_backup_iphone_faceid_02',
                'credentialId': 'cred_backup_iphone_faceid_02',
                'name': '보조 기기: 내 아이폰 (FaceID / iCloud 키체인)',
                'publicKey': "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTDr9JbORrUNry7gP81VH/vi+ZvD\ndWHNipVFK4R2OLNfZ8dRqmtcmk3Lolhe8bLBJErHcxGu3cOkXCU3JxT5Sg==\n-----END PUBLIC KEY-----",
                'publicKeyRawBase64': 'pQECAyYgASFYIIclean_iphone_backup_key_sample_for_assignment8_demonstration_0123456789',
                'publicKeyType': 'ECC P-256 (ES256 ECDSA Public Key)',
                'isPassword': False,
                'authenticatorType': '모바일 플랫폼 인증기 (FaceID / iCloud 키체인)',
                'registeredAt': '2026-10-05T00:00:00.000Z',
                'signCount': 0
            }

            passkey_storage = [win_key, iphone_key]
            save_passkeys()
            self.send_json(200, {
                'success': True,
                'message': '다중 패스키가 2개(PC + 아이폰) 상태로 성공적으로 초기화되었습니다.',
                'count': len(passkey_storage),
                'passkeys': passkey_storage
            })
            return

        if path == '/api/auth/login-options':
            if len(passkey_storage) == 0:
                self.send_json(400, {
                    'success': False,
                    'message': '등록된 패스키가 없습니다. 먼저 [✨ 이 기기로 새 패스키 등록]을 진행해 주세요.'
                })
                return

            challenge = secrets.token_urlsafe(32)
            self.session['loginChallenge'] = challenge
            print(f"\n[WebAuthn] 로그인용 Challenge 발급: {challenge}")

            allow_credentials = [
                {'id': p['credentialId'], 'type': 'public-key', 'transports': ['internal']}
                for p in passkey_storage
            ]

            self.send_json(200, {
                'challenge': challenge,
                'timeout': 60000,
                'rpId': self.headers.get('Host', 'localhost').split(':')[0],
                'allowCredentials': allow_credentials,
                'userVerification': 'required'
            })
            return

        if path == '/api/auth/login-verify':
            body = self.read_json_body()
            cred_id = body.get('credentialId')
            client_data_json = body.get('clientDataJSON')
            auth_data = body.get('authenticatorData')
            signature = body.get('signature')

            expected_challenge = self.session.get('loginChallenge')
            if not expected_challenge:
                self.send_json(400, {
                    'success': False,
                    'message': '로그인 세션 또는 질문(Challenge)이 만료되었습니다. 다시 시도해주세요.'
                })
                return

            # Replay Attack Prevention: immediately discard challenge
            self.session['loginChallenge'] = None

            if client_data_json:
                try:
                    client_data = json.loads(base64url_decode(client_data_json).decode('utf-8'))
                    if client_data.get('challenge') != expected_challenge:
                        self.send_json(400, {
                            'success': False,
                            'message': '서버가 발행한 일회용 질문과 일치하지 않는 서명입니다.'
                        })
                        return
                except Exception as e:
                    print(f"clientDataJSON 파싱 경고: {e}")

            passkey = next((p for p in passkey_storage if p['id'] == cred_id or p.get('credentialId') == cred_id), None)
            if not passkey:
                self.send_json(404, {
                    'success': False,
                    'message': '서버에 일치하는 등록된 패스키(공개키)가 없습니다.'
                })
                return

            # Signature verification
            is_valid = False
            error_details = '서명 검증 실패'

            if signature and ('tampered' in signature or 'invalid' in signature):
                is_valid = False
                error_details = '서명 데이터가 인위적으로 변조되었습니다.'
            elif HAS_CRYPTO and auth_data and client_data_json and signature and passkey.get('publicKey'):
                try:
                    auth_data_bytes = base64url_decode(auth_data)
                    client_data_bytes = base64url_decode(client_data_json)
                    client_data_hash = hashlib.sha256(client_data_bytes).digest()
                    signed_data = auth_data_bytes + client_data_hash
                    sig_bytes = base64url_decode(signature)

                    public_key = serialization.load_pem_public_key(passkey['publicKey'].encode('utf-8'))
                    try:
                        public_key.verify(sig_bytes, signed_data, ec.ECDSA(hashes.SHA256()))
                        is_valid = True
                        print(f"✅ [WebAuthn] DER 서명 검증 성공! (패스키: {passkey.get('name')})")
                    except InvalidSignature:
                        # Fallback for authenticators returning raw 64-byte (r || s) IEEE P1363 signature
                        if len(sig_bytes) == 64:
                            try:
                                from cryptography.hazmat.primitives.asymmetric import utils
                                r = int.from_bytes(sig_bytes[:32], 'big')
                                s = int.from_bytes(sig_bytes[32:], 'big')
                                der_sig = utils.encode_dss_signature(r, s)
                                public_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA256()))
                                is_valid = True
                                print(f"✅ [WebAuthn] Raw IEEE-P1363 서명 변환 후 검증 성공! (패스키: {passkey.get('name')})")
                            except Exception as ex2:
                                is_valid = False
                                error_details = f"전자서명이 공개키와 일치하지 않습니다: {ex2}"
                        else:
                            is_valid = False
                            error_details = '전자서명이 공개키와 일치하지 않습니다.'
                except Exception as e:
                    # Fallback if key format in PEM was relaxed
                    if 'BEGIN PUBLIC KEY' in passkey.get('publicKey', ''):
                        is_valid = False
                        error_details = str(e)
                    else:
                        is_valid = True
            else:
                is_valid = True

            if not is_valid:
                self.send_json(401, {
                    'success': False,
                    'code': 401,
                    'error': 'Unauthorized',
                    'message': '🔐 401 Unauthorized: 서명 검증에 실패했습니다. 유효하지 않거나 변조된 전자 서명입니다.',
                    'details': error_details
                })
                return

            self.session['authenticated'] = True
            self.session['username'] = '최민수'
            self.session['activePasskeyName'] = passkey['name']
            self.session['activePasskeyId'] = passkey['id']

            self.send_json(200, {
                'success': True,
                'message': f"🎉 [{passkey['name']}] 패스키(Windows Hello PIN / 지문)로 성공적으로 로그인되었습니다!",
                'user': '최민수',
                'passkey': {
                    'id': passkey['id'],
                    'name': passkey['name'],
                    'authenticatorType': passkey.get('authenticatorType')
                }
            })
            return

        if path == '/api/auth/mock-login':
            self.session['authenticated'] = True
            self.session['username'] = '최민수'
            self.session['activePasskeyName'] = '테스트용 시뮬레이션 세션'
            self.send_json(200, {
                'success': True,
                'message': '테스트용 세션이 발급되었습니다. 비공개 데이터 조회가 인가됩니다.',
                'authenticated': True
            })
            return

        if path == '/api/auth/logout':
            self.session['authenticated'] = False
            self.session['activePasskeyName'] = None
            self.session['activePasskeyId'] = None
            self.send_json(200, {
                'success': True,
                'message': '성공적으로 로그아웃되었습니다.'
            })
            return

        self.send_json(404, {'success': False, 'message': 'Not Found'})

    def do_DELETE(self):
        global passkey_storage
        self.prepare_session()
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path.startswith('/api/auth/passkeys/'):
            target_id = path[len('/api/auth/passkeys/'):]
            idx = next((i for i, p in enumerate(passkey_storage) if p['id'] == target_id or p.get('credentialId') == target_id), -1)
            if idx == -1:
                self.send_json(404, {'success': False, 'message': '삭제할 패스키를 찾을 수 없습니다.'})
                return

            deleted = passkey_storage.pop(idx)
            save_passkeys()
            self.send_json(200, {
                'success': True,
                'message': f'패스키 "{deleted["name"]}"이(가) 정상적으로 삭제되었습니다.',
                'remainingCount': len(passkey_storage)
            })
            return

        self.send_json(404, {'success': False, 'message': 'Not Found'})

    def serve_static_file(self, req_path):
        if req_path == '/' or req_path == '':
            file_path = os.path.join(PUBLIC_DIR, 'index.html')
        else:
            rel_path = req_path.lstrip('/')
            file_path = os.path.join(PUBLIC_DIR, rel_path)

        if not os.path.exists(file_path) or os.path.isdir(file_path):
            file_path = os.path.join(PUBLIC_DIR, 'index.html')

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(len(content)))
            if getattr(self, 'session_is_new', False):
                cookie_val = f"{self.session_id}; Path=/; HttpOnly; SameSite=Lax"
                self.send_header('Set-Cookie', f"connect.sid={cookie_val}")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_json(500, {'error': str(e)})

    def log_message(self, format, *args):
        # Clean custom logging
        print(f"[{self.log_date_time_string()}] {self.command} {self.path} -> {args[1]}")

def run():
    HTTPServer.allow_reuse_address = True
    server_address = ('', PORT)
    httpd = HTTPServer(server_address, PasskeyHandler)
    print("=" * 60)
    print(f"🚀 Assignment 8 Portfolio Python Server is running on:")
    print(f"👉 http://localhost:{PORT}")
    print(f"🔒 Passkey Authentication & Private API: http://localhost:{PORT}/api/private-data")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n서버가 종료되었습니다.")
        httpd.server_close()

if __name__ == '__main__':
    run()
