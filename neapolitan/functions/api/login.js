export async function onRequestPost({ request, env }) {
  const formData = await request.formData();
  const pw = formData.get('password')?.toString() || '';
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  const key = `fail:${ip}`;
  let record = await env.ATTEMPTS.get(key, { type: 'json' }) || { count:0, penaltyUntil:0 };

  const now = Date.now();
  if (record.penaltyUntil && now < record.penaltyUntil) {
    return new Response(JSON.stringify({
      ok:false, stage:'penalty',
      message:'당신의 카르마에 의하여, 당신은 앞으로 일정 시간 동안 게임에 참여하실 수 없습니다.',
      until: record.penaltyUntil
    }), { status:403, headers:{'Content-Type':'application/json'} });
  }

  if (pw === env.PASSWORD) {
    await env.ATTEMPTS.delete(key);
    return new Response(JSON.stringify({ ok:true, stage:'success' }), { status:200 });
  }

  record.count++;
  let stage='normal', message='부탁입니다. 신중하게 시도해주세요.';

  if (record.count===5) {
    stage='warn1'; message='무작정 계속 시도하는 것은 섣부른 행동입니다.';
  } else if (record.count===8) {
    stage='warn2'; message='경고합니다. 적법한 루트로 출입하십시오.';
  } else if (record.count>=10) {
    stage='penalty'; 
    const penaltyMs=24*60*60*1000;
    record.penaltyUntil=now+penaltyMs;
    message='당신의 카르마에 의하여, 당신은 앞으로 24시간 동안 게임에 참여하실 수 없습니다.';
  }

  await env.ATTEMPTS.put(key, JSON.stringify(record), { expirationTtl: 24*60*60 });
  return new Response(JSON.stringify({ ok:false, stage, message, count:record.count, until:record.penaltyUntil }), { status:401, headers:{'Content-Type':'application/json'} });
}
