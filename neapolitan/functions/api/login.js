/**
 * 로그인 API (최종)
 * - env.PASSWORD 검증
 * - 실패 횟수(IP 기준) 누적 → warn1(>=5), warn2(>=8), penalty(>=10, 24h)
 * - penalty/banned: banUntil(ms) 기준으로 남은 시간 ttl 반환
 * - penalty 중엔 비번이 맞아도 차단
 * 필요: Environment variable PASSWORD, KV Binding ATTEMPTS
 */
export async function onRequestPost({ request, env }) {
  const form = await request.formData();
  const pw = (form.get('password') || '').toString();
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('CF-Connecting-IP') || 'unknown';

  const key = `fail:${ip}`;
  let record = await env.ATTEMPTS.get(key, { type: 'json' });
  if (!record) record = { count: 0, penaltyUntil: 0 };

  const now = Date.now();

  // 0) 이미 패널티 중?
  if (record.penaltyUntil && now < record.penaltyUntil) {
    return new Response(JSON.stringify({
      ok: false, stage: 'penalty',
      message: '당신의 카르마에 의하여, 당신은 앞으로 24시간 동안 게임에 참여하실 수 없습니다.',
      until: record.penaltyUntil
    }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  } else if (record.penaltyUntil && now >= record.penaltyUntil) {
    // 만료 정리
    record.penaltyUntil = 0;
    record.count = 0;
    await env.ATTEMPTS.put(key, JSON.stringify(record), { expirationTtl: 24 * 60 * 60 });
  }

  // 1) 비밀번호 일치
  if (pw === env.PASSWORD) {
    await env.ATTEMPTS.delete(key);
    return new Response(JSON.stringify({ ok: true, stage: 'success' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'auth=ok; Path=/; HttpOnly; Secure; Max-Age=86400; SameSite=Lax'
      }
    });
  }

  // 2) 실패 → 누적(+1)
  record.count += 1;

  // 3) 임계치 분기 (>= 사용)
  if (record.count >= 10) {
    if (!record.penaltyUntil || now >= record.penaltyUntil) {
      record.penaltyUntil = now + 24 * 60 * 60 * 1000; // 24h ms
    }
    await env.ATTEMPTS.put(key, JSON.stringify(record), { expirationTtl: 24 * 60 * 60 });
    return new Response(JSON.stringify({
      ok: false, stage: 'penalty',
      message: '당신의 카르마에 의하여, 당신은 앞으로 24시간 동안 게임에 참여하실 수 없습니다.',
      until: record.penaltyUntil
    }), { status: 429, headers: { 'Content-Type': 'application/json' } });
  }

  if (record.count >= 8) {
    await env.ATTEMPTS.put(key, JSON.stringify(record), { expirationTtl: 24 * 60 * 60 });
    return new Response(JSON.stringify({
      ok: false, stage: 'warn2',
      message: '경고합니다. 적법한 루트로 출입하십시오.',
      count: record.count
    }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  if (record.count >= 5) {
    await env.ATTEMPTS.put(key, JSON.stringify(record), { expirationTtl: 24 * 60 * 60 });
    return new Response(JSON.stringify({
      ok: false, stage: 'warn1',
      message: '무작정 계속 시도하는 것은 섣부른 행동입니다.',
      count: record.count
    }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // 기본 실패
  await env.ATTEMPTS.put(key, JSON.stringify(record), { expirationTtl: 24 * 60 * 60 });
  return new Response(JSON.stringify({
    ok: false, stage: 'normal',
    message: '부탁입니다. 신중하게 시도해주세요.',
    count: record.count
  }), { status: 401, headers: { 'Content-Type': 'application/json' } });
}
