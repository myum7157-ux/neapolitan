/**
 * Cloudflare Pages Functions: /api/comments
 *
 * 필요한 바인딩 / 환경변수 (Pages → Settings → Functions):
 *  - KV namespace: COMMENTS         (키-값 저장소)
 *  - Text env:     OWNER_PASSWORD   (운영자 비번, DELETE 권한)
 *  - (선택) Text:  SECRET_SALT      (IP 해시용 추가 소금)
 *
 * 쿠키:
 *  - auth=ok  → 로그인 성공 시 /api/login 이 심어줌. 이 쿠키 있어야 POST 가능.
 */

export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();

  // ----- 유틸 -----
  const json = (obj, init = 200, headers = {}) =>
    new Response(JSON.stringify(obj), {
      status: init,
      headers: { "Content-Type": "application/json", ...headers },
    });

  const bad = (msg, code = 400) => json({ ok: false, error: msg }, code);

  async function sha256(s) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  function getIp(req) {
    // Cloudflare가 원 IP를 헤더로 넘겨줌
    return (
      req.headers.get("cf-connecting-ip") ||
      req.headers.get("CF-Connecting-IP") ||
      "0.0.0.0"
    );
  }

  async function ipHash(req) {
    const ip = getIp(req);
    const salt = env.SECRET_SALT || "";
    return await sha256(ip + "|" + salt);
  }

  // ----- KV helper -----
  async function getOrder() {
    const s = await env.COMMENTS.get("order");
    return s ? JSON.parse(s) : [];           // 예: [1,2,3,...] (표시 순서)
  }
  async function setOrder(arr) {
    await env.COMMENTS.put("order", JSON.stringify(arr));
  }
  async function getComment(id) {
    const s = await env.COMMENTS.get(`c:${id}`);
    return s ? JSON.parse(s) : null;         // { text, ts }
  }
  async function setComment(id, obj) {
    await env.COMMENTS.put(`c:${id}`, JSON.stringify(obj));
  }
  async function delComment(id) {
    await env.COMMENTS.delete(`c:${id}`);
  }

  // ----- 라우팅 -----
  if (method === "GET") {
    const order = await getOrder();
    const out = [];
    for (const id of order) {
      const c = await getComment(id);
      if (c) out.push({ id, by: `탈출자 ${id}`, text: c.text, ts: c.ts });
    }
    return json(out);
  }

  if (method === "POST") {
    // 1) 로그인 쿠키 확인
    const cookie = request.headers.get("Cookie") || "";
    const hasAuth = /(?:^|;\s*)auth=ok(?:;|$)/.test(cookie);
    if (!hasAuth) return bad("인증되지 않은 요청입니다.", 401);

    // 2) 요청 바디 파싱
    let body = {};
    try {
      body = await request.json();
    } catch (_) {
      return bad("JSON 본문이 필요합니다.");
    }
    const raw = (body.text || "").toString().trim();
    if (!raw) return bad("내용을 입력하세요.");
    if (raw.length > 400) return bad("내용이 너무 깁니다. (최대 400자)");

    // 3) 1인 1회 제한: IP 해시로 체크
    const ipH = await ipHash(request);
    const already = await env.COMMENTS.get(`by:${ipH}`);
    if (already) return bad("이미 코멘트를 작성하셨습니다.", 429);

    // 4) 저장
    const order = await getOrder();
    const newId = order.length + 1;
    await setComment(newId, { text: raw, ts: Date.now() });
    order.push(newId);
    await setOrder(order);
    await env.COMMENTS.put(`by:${ipH}`, "1"); // 플래그만 저장 (아이디는 필요 없음)

    return json({ ok: true, id: newId });
  }

  if (method === "DELETE") {
    // 운영자 인증 (Authorization: Bearer <OWNER_PASSWORD>)
    const authz = request.headers.get("Authorization") || "";
    const token = authz.startsWith("Bearer ") ? authz.slice(7) : "";
    if (!token || token !== String(env.OWNER_PASSWORD || "")) {
      return bad("관리자 권한이 없습니다.", 401);
    }

    let body = {};
    try {
      body = await request.json();
    } catch (_) {}
    const id = parseInt(body.id, 10);
    if (!id || id < 1) return bad("유효한 id가 필요합니다.");

    // 현재 순서에서 제거
    const order = await getOrder();
    const idx = order.indexOf(id);
    if (idx === -1) return bad("해당 id를 찾을 수 없습니다.", 404);

    const remaining = order.filter(x => x !== id);

    // 연속 번호로 재배열 (1..N) — 내용 복사 후 원본 삭제
    // 예: 남은 순서가 [3,5,9] 이면, 1←3, 2←5, 3←9 로 재번호 부여
    for (let i = 0; i < remaining.length; i++) {
      const targetId = i + 1;
      const srcId = remaining[i];
      if (srcId === targetId) continue; // 이미 맞는 번호면 스킵
      const c = await getComment(srcId);
      if (c) {
        await setComment(targetId, c);
        await delComment(srcId);
      }
    }

    // 삭제된 마지막 큰 번호가 남아있을 수 있으므로 정리
    const newCount = remaining.length;
    // 혹시 원래 id보다 큰 것들 정리
    for (let k = newCount + 1; k <= order.length; k++) {
      await delComment(k).catch(() => {});
    }

    // 새 순서 저장: [1,2,...,newCount]
    await setOrder(Array.from({ length: newCount }, (_, i) => i + 1));

    return json({ ok: true });
  }

  // 허용하지 않는 메서드
  return new Response("Method Not Allowed", { status: 405 });
}
