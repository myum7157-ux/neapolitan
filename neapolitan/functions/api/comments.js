// KV 바인딩: env.COMMENTS
// 환경변수: env.OWNER_PASSWORD (운영자 삭제용), env.SECRET_SALT (IP 해시용, 임의의 긴 문자열)

export async function onRequest({ request, env }) {
  const { COMMENTS, OWNER_PASSWORD = "", SECRET_SALT = "" } = env;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  const json = (x, s = 200) =>
    new Response(JSON.stringify(x), {
      status: s,
      headers: { "Content-Type": "application/json" },
    });

  // utils
  const sha256 = async (s) => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  };
  const ipHash = async (req) => {
    const ip =
      req.headers.get("cf-connecting-ip") ||
      req.headers.get("CF-Connecting-IP") ||
      "0.0.0.0";
    return sha256(SECRET_SALT + "|" + ip);
  };

  // ===== GET: 목록 (페이지네이션, 오래된→최신) =====
  if (method === "GET") {
    const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10));
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") || "20", 10)));

    const idx = JSON.parse((await COMMENTS.get("idx")) || "[]"); // [1,2,3,...]
    const total = idx.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const curPage = Math.min(page, totalPages);

    const start = (curPage - 1) * limit;
    const end = curPage * limit;
    const slice = idx.slice(start, end); // 오래된→최신 유지

    const items = [];
    for (const id of slice) {
      const raw = await COMMENTS.get(`c:${id}`);
      if (raw) items.push(JSON.parse(raw));
    }

    return json({ total, page: curPage, limit, items });
  }

  // ===== POST: 작성 =====
  if (method === "POST") {
    if (!/application\/json/i.test(request.headers.get("content-type") || "")) {
      return json({ error: "INVALID_CONTENT_TYPE" }, 415);
    }
    const body = await request.json().catch(() => ({}));
    let text = String(body.text || "");

    // 0) 기본 정리
    text = text
      .replace(/[\u200B-\u200D\uFEFF]/g, "") // zero-width 제거
      .replace(/\s{3,}/g, " ")              // 과다 공백 축약
      .trim();

    // 1) 길이 제한 (하드컷)
    const MAX_LEN = 300;
    if (!text) return json({ error: "내용이 비었습니다." }, 400);
    if (text.length > MAX_LEN) return json({ error: `댓글은 ${MAX_LEN}자 이내로 제한됩니다.` }, 400);

    // 2) 같은 글자/문자열 반복 축약 → 도배 방지
    // - 동일 문자 20회 이상 연속 → 20회로 축약
    text = text.replace(/(.)\1{20,}/g, (m, ch) => ch.repeat(20));

    // 3) 문자열 구성 검사 (한자/특수문자 과다 도배 필터 - 느슨)
    const hanjaCount = (text.match(/[\u4E00-\u9FFF]/g) || []).length;
    if (hanjaCount / text.length > 0.6) {
      return json({ error: "허용되지 않는 문자 도배입니다." }, 400);
    }

    // 4) IP 단위 1인 1회 + 짧은 재시도 레이트 리밋
    const who = await ipHash(request);
    const used = await COMMENTS.get(`by:${who}`);
    if (used) return json({ error: "이미 작성하셨습니다. (1인 1회)" }, 409);

    // 짧은 시간 연속 POST 차단 (10초)
    const hotKey = `hot:${who}`;
    const hot = await COMMENTS.get(hotKey);
    if (hot) return json({ error: "잠시 후 다시 시도해 주세요." }, 429);

    // 5) 저장
    const idx = JSON.parse((await COMMENTS.get("idx")) || "[]");
    const nextId = idx.length ? Math.max(...idx) + 1 : 1;

    const item = { id: nextId, by: `탈출자 ${nextId}`, text, ts: Date.now() };
    idx.push(nextId);

    await COMMENTS.put("idx", JSON.stringify(idx));
    await COMMENTS.put(`c:${nextId}`, JSON.stringify(item));
    // 1년 동안 재작성 금지
    await COMMENTS.put(`by:${who}`, String(nextId), { expirationTtl: 60 * 60 * 24 * 365 });
    // 10초 쿨타임
    await COMMENTS.put(hotKey, "1", { expirationTtl: 10 });

    return json({ ok: true, item });
  }

  // ===== DELETE: 운영자 삭제 (번호 당겨짐) =====
  if (method === "DELETE") {
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (!OWNER_PASSWORD || token !== OWNER_PASSWORD) return json({ error: "FORBIDDEN" }, 403);

    const { id } = await request.json().catch(() => ({}));
    const num = parseInt(id, 10);
    if (!num) return json({ error: "INVALID_ID" }, 400);

    const idx = JSON.parse((await COMMENTS.get("idx")) || "[]");
    const pos = idx.indexOf(num);
    if (pos === -1) return json({ error: "NOT_FOUND" }, 404);

    // idx에서 제거
    idx.splice(pos, 1);
    await COMMENTS.put("idx", JSON.stringify(idx));
    await COMMENTS.delete(`c:${num}`);

    return json({ ok: true });
  }

  return json({ error: "Method Not Allowed" }, 405);
      }
