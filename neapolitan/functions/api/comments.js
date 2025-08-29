/**
 * 코멘트 API (KV 기반, 1인 1회, 삭제 시 재번호 부여)
 * - GET /api/comment : { items:[{id,text,t,n}], already:bool }
 * - POST /api/comment : body={ text } (auth=ok 쿠키 필수, 1회 제한)
 * - DELETE /api/comment : body={ id, admin } (admin=OWNER_PASSWORD)
 *
 * KV 바인딩: env.COMMENTS
 * 환경변수 : env.SECRET_SALT (선택), env.OWNER_PASSWORD (필수), auth 쿠키는 /api/login에서 발급
 *
 * 저장 구조:
 * - "idx" : JSON 배열 [id1,id2,...] (표시 순서)
 * - "c:<id>" : JSON { id, text, t } (단일 코멘트)
 * - "by:<ipHash>" : "<id>" (1인 1회 방지)
 * - "who:<id>" : "<ipHash>" (역방향: 삭제 시 1회 제한도 해제 가능)
 */

export async function onRequest({ request, env }) {
  const { COMMENTS, OWNER_PASSWORD, SECRET_SALT = "s" } = env;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  // util
  async function sha256(s) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  }
  async function ipHash(req) {
    const ip =
      req.headers.get("cf-connecting-ip") ||
      req.headers.get("CF-Connecting-IP") ||
      "0.0.0.0";
    return sha256(`${SECRET_SALT}|${ip}`);
  }
  async function loadIndex() {
    const raw = await COMMENTS.get("idx");
    return raw ? JSON.parse(raw) : [];
  }
  async function saveIndex(arr) {
    await COMMENTS.put("idx", JSON.stringify(arr));
  }

  // GET: 목록 + 현재 사용자 이미 작성여부
  if (method === "GET") {
    const idx = await loadIndex();
    // 최신순으로 보여주고 싶으면 reverse() 하세요. 지금은 등록순.
    const items = [];
    for (let i = 0; i < idx.length; i++) {
      const id = idx[i];
      const c = await COMMENTS.get(`c:${id}`, { type: "json" });
      if (c) items.push({ ...c, n: i + 1 }); // 여기서 번호를 붙임
    }
    const h = await ipHash(request);
    const already = !!(await COMMENTS.get(`by:${h}`));
    return new Response(JSON.stringify({ items, already }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // POST: 작성(1인 1회, auth=ok 쿠키 필요)
  if (method === "POST") {
    const cookie = request.headers.get("Cookie") || "";
    const authed = /(?:^|;\s*)auth=ok(?:;|$)/.test(cookie);
    if (!authed) {
      return new Response(JSON.stringify({ ok: false, message: "unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const { text } = await request.json().catch(() => ({}));
    const t = (text || "").toString().trim();
    if (!t || t.length > 300) {
      return new Response(JSON.stringify({ ok: false, message: "1~300자만 허용" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const h = await ipHash(request);
    const exists = await COMMENTS.get(`by:${h}`);
    if (exists) {
      return new Response(JSON.stringify({ ok: false, already: true, message: "이미 코멘트를 남기셨습니다." }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      });
    }

    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const item = { id, text: t, t: Date.now() };

    // index 뒤에 추가(등록순)
    const idx = await loadIndex();
    idx.push(id);
    await saveIndex(idx);

    await COMMENTS.put(`c:${id}`, JSON.stringify(item));
    await COMMENTS.put(`by:${h}`, id);
    await COMMENTS.put(`who:${id}`, h);

    // n은 클라이언트에 알려주기 위해 계산해서 내려줌
    return new Response(JSON.stringify({ ok: true, item: { ...item, n: idx.length } }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  // DELETE: 운영자 삭제(OWNER_PASSWORD 검증) → 재번호는 목록 만들 때 자동 처리
  if (method === "DELETE") {
    const { id, admin } = await request.json().catch(() => ({}));
    if (!id || !admin) {
      return new Response(JSON.stringify({ ok: false, message: "id/admin 필요" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (admin !== OWNER_PASSWORD) {
      return new Response(JSON.stringify({ ok: false, message: "forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 인덱스에서 제거
    const idx = await loadIndex();
    const pos = idx.indexOf(id);
    if (pos === -1) {
      return new Response(JSON.stringify({ ok: false, message: "not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }
    idx.splice(pos, 1);
    await saveIndex(idx);

    // 데이터 삭제
    const who = await COMMENTS.get(`who:${id}`);
    if (who) await COMMENTS.delete(`by:${who}`);
    await COMMENTS.delete(`who:${id}`);
    await COMMENTS.delete(`c:${id}`);

    return new Response(JSON.stringify({ ok: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  return new Response("Method not allowed", { status: 405 });
}
