// functions/api/comments.js
// KV 바인딩: env.COMMENTS
// 환경변수: env.OWNER_PASSWORD (운영자 삭제용), env.SECRET_SALT (IP 해시용, 임의 문자열 권장)

export async function onRequest({ request, env }) {
  const { COMMENTS, OWNER_PASSWORD = "", SECRET_SALT = "" } = env;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  // -------- helpers --------
  const json = (x, s = 200, extraHeaders = {}) =>
    new Response(JSON.stringify(x), {
      status: s,
      headers: { "Content-Type": "application/json", ...extraHeaders },
    });

  const sha256 = async (s) => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("");
  };

  const ipHash = async (req) => {
    const ip =
      req.headers.get("cf-connecting-ip") ||
      req.headers.get("CF-Connecting-IP") ||
      "0.0.0.0";
    return await sha256(`${SECRET_SALT}|${ip}`);
  };

  // 도배/깨짐 방지 포함 sanitize
  const sanitizeText = (input) => {
    let s = input;
    if (typeof s !== "string") s = "";                    // ← undefined/null 방어
    s = s.replace(/[\u0000-\u001F\u007F]/g, "");          // 제어문자 제거
    s = s.replace(/[\u200B-\u200D\uFEFF]/g, "");          // zero-width 제거
    s = s.replace(/\r\n?/g, "\n");                        // 개행 정규화
    s = s.replace(/[ \t]{3,}/g, "  ");                    // 과도한 공백 축약
    s = s.replace(/(\S)\1{19,}/g, (m, c) => c.repeat(20)); // 같은 문자 20회 초과 축약
    // 라인/총길이 제한
    const MAX_LEN = 300;
    const MAX_LINES = 12;
    const MAX_PER_LINE = 120;
    s = s.slice(0, MAX_LEN + 50); // 여유컷 → 아래에서 다시 잘라줌
    let lines = s.split("\n").slice(0, MAX_LINES);
    lines = lines.map(L => L.slice(0, MAX_PER_LINE));
    s = lines.join("\n").trim();
    if (s.length > MAX_LEN) s = s.slice(0, MAX_LEN).trim();
    return s;
  };

  // 안전 파서(깨진 JSON/레코드 스킵)
  const safeParse = (str) => {
    try { return JSON.parse(str); } catch { return null; }
  };

  // -------- GET: 목록 (오래된 → 최신, 페이지네이션) --------
  if (method === "GET") {
    const page  = Math.max(1, parseInt(url.searchParams.get("page")  || "1", 10));
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") || "20", 10)));

    const idx = safeParse(await COMMENTS.get("idx")) || []; // [1,2,3,...] 누적
    const total = idx.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const curPage = Math.min(page, totalPages);

    const start = (curPage - 1) * limit;
    const end   = curPage * limit;
    const slice = idx.slice(start, end); // 오래된→최신 유지

    const items = [];
    for (const id of slice) {
      const raw = await COMMENTS.get(`c:${id}`);
      if (!raw) continue;
      const obj = safeParse(raw);
      if (!obj) continue;
      if (typeof obj.text !== "string") obj.text = ""; // 결손 필드 보강
      items.push(obj);
    }

    return json({ total, page: curPage, limit, items });
  }

  // -------- POST: 작성 (1인 1회) --------
  if (method === "POST") {
    if (!/application\/json/i.test(request.headers.get("content-type") || "")) {
      return json({ error: "INVALID_CONTENT_TYPE" }, 415);
    }
    const body = await request.json().catch(() => ({}));
    let text = sanitizeText(body?.text);

    if (!text) return json({ error: "내용이 비었습니다." }, 400);
    if (text.length > 300) return json({ error: "댓글은 300자 이내로 제한됩니다." }, 400);

    // 1인 1회 차단
    const who = await ipHash(request);
    const used = await COMMENTS.get(`by:${who}`);
    if (used) return json({ error: "이미 작성하셨습니다. (1인 1회)" }, 409);

    // 다음 ID
    const idx = safeParse(await COMMENTS.get("idx")) || [];
    const nextId = idx.length ? Math.max(...idx) + 1 : 1;

    const item = { id: nextId, by: `탈출자 ${nextId}`, text, ts: Date.now() };
    idx.push(nextId);

    // 저장(트랜잭션처럼 순서대로)
    await COMMENTS.put(`c:${nextId}`, JSON.stringify(item));
    await COMMENTS.put("idx", JSON.stringify(idx));
    // 재시도 방지 토큰(1년)
    await COMMENTS.put(`by:${who}`, String(nextId), { expirationTtl: 60 * 60 * 24 * 365 });

    return json({ ok: true, item });
  }

  // -------- DELETE: 운영자 삭제 (빈자리 당겨짐) --------
  if (method === "DELETE") {
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (!OWNER_PASSWORD || token !== OWNER_PASSWORD) {
      return json({ error: "FORBIDDEN" }, 403);
    }

    const body = await request.json().catch(() => ({}));
    const id = parseInt(body?.id, 10);
    if (!id) return json({ error: "INVALID_ID" }, 400);

    const idx = safeParse(await COMMENTS.get("idx")) || [];
    const pos = idx.indexOf(id);
    if (pos === -1) return json({ error: "NOT_FOUND" }, 404);

    idx.splice(pos, 1); // 자리 당김
    await COMMENTS.put("idx", JSON.stringify(idx));
    await COMMENTS.delete(`c:${id}`);

    // 해당 IP 1회 제한 해제(선택): 누가 썼는지 역추적은 안 하므로 생략
    return json({ ok: true });
  }

  return json({ error: "Method Not Allowed" }, 405);
}
