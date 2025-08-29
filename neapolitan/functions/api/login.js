/**
 * 로그인 API (최종본)
 * - 비번 검증 (env.PASSWORD)
 * - 실패 횟수(IP 기준) 누적 → 경고1/경고2/패널티(24h 밴)
 * - 패널티/밴 시 남은 시간 TTL을 초 단위로 전달
 *
 * 필요 환경:
 * 1) Environment variable: PASSWORD
 * 2) KV Binding: ATTEMPTS (Settings → Functions → KV namespaces → Add binding)
 */

const WARN1 = 5; // 경고 1 시작
const WARN2 = 8; // 경고 2 시작
const BAN_AT = 10; // 패널티 시작(=밴)
const BAN_TTL = 60 * 60 * 24; // 패널티 유지 시간(초): 24h
const FAIL_TTL = 60 * 60; // 실패 카운트 유지 시간(초): 1h (원하면 24h = 86400 로)

function ipFrom(req) {
  // Cloudflare가 넣어주는 실제 클라이언트 IP
  return req.headers.get('CF-Connecting-IP') || 'unknown';
}

/** 실패 횟수 +1 (TTL 유지) → 최신값 반환 */
async function incAndGet(env, key, ttlSeconds) {
  const current = parseInt((await env.ATTEMPTS.get(key)) || '0', 10);
  const next = current + 1;
  await env.ATTEMPTS.put(key, String(next), { expirationTtl: ttlSeconds });
  return next;
}

/** 남은 TTL(초)를 계산해서 반환 (KV get은 값만 주므로 키를 갱신하며 TTL 재설정하지 않도록 주의) */
async function getRemainingTTLSeconds(env, key, defaultTtl) {
  // KV는 남은 TTL 조회 API가 없어서, 여기서는 최초 세팅값을 그대로 전달.
  // (요청 시마다 TTL이 줄어드는 정확한 값이 필요하면 Durable Objects/Turnstile 등 다른 저장소 필요)
  // 간단 버전: 항상 defaultTtl(=BAN_TTL)을 내려서 "최대 남은 시간"을 안내.
  return defaultTtl;
}

export async function onRequestPost({ request, env }) {
  const form = await request.formData();
  const pw = (form.get('password') || '').toString();
  const ip = ipFrom(request);

  const failKey = `a:${ip}`;
  const banKey = `ban:${ip}`;

  // 0) 이미 밴?
  const banned = await env.ATTEMPTS.get(banKey);
  if (banned) {
    const ttl = await getRemainingTTLSeconds(env, banKey, BAN_TTL);
    return new Response(JSON.stringify({
      ok: false,
      stage: 'banned',
      ttl
    }), { status: 403, headers: { 'Content-Type': 'application/json' }});
  }

  // 1) 비번 검증
  if (pw === env.PASSWORD) {
    // 성공 → 실패카운트 초기화 + auth 쿠키 세팅
    await env.ATTEMPTS.delete(failKey);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'auth=ok; Path=/; HttpOnly; Secure; Max-Age=86400; SameSite=Lax'
      }
    });
  }

  // 2) 실패 → 카운트 +1
  const count = await incAndGet(env, failKey, FAIL_TTL);

  // 3) 단계 분기
  if (count >= BAN_AT) {
    // 패널티(밴 기록)
    await env.ATTEMPTS.put(banKey, '1', { expirationTtl: BAN_TTL });
    const ttl = BAN_TTL; // 단순 안내(최대 남은 시간)
    return new Response(JSON.stringify({
      ok: false,
      stage: 'penalty',
      ttl
    }), { status: 429, headers: { 'Content-Type': 'application/json' }});
  }

  if (count >= WARN2) {
    return new Response(JSON.stringify({
      ok: false,
      stage: 'warn2',
      message: '경고합니다. 적법한 루트로 출입하십시오.'
    }), { status: 401, headers: { 'Content-Type': 'application/json' }});
  }

  if (count >= WARN1) {
    return new Response(JSON.stringify({
      ok: false,
      stage: 'warn1',
      message: '무작정 계속 시도하는 것은 섣부른 행동입니다.'
    }), { status: 401, headers: { 'Content-Type': 'application/json' }});
  }

  // 기본 실패
  return new Response(JSON.stringify({
    ok: false,
    stage: 'normal',
    message: '부탁입니다. 신중하게 해주세요.',
    count
  }), { status: 401, headers: { 'Content-Type': 'application/json' }});
}
