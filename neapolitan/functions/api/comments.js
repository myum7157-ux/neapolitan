// KV 바인딩: env.COMMENTS
// 기존 데이터(idx / c:<id>) 그대로 사용 → 기존 댓글 유지

export async function onRequest({ request, env }) {
  const { COMMENTS, OWNER_PASSWORD = "", SECRET_SALT = "" } = env;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  const json = (x, s = 200) =>
    new Response(JSON.stringify(x), {
      status: s,
      headers: { "Content-Type": "application/json" },
    });

  // 간단 IP 해시
  const sha256 = async (s) => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };
  const ipHash = async (req) => {
    const ip = req.headers.get("cf-connecting-ip") || req.headers.get("CF-Connecting-IP") || "0.0.0.0";
    return await sha256(SECRET_SALT + "|" + ip);
  };

  // 텍스트 정리
  const sanitize = (s) =>
    String(s)
      .replace(/[\u200B-\u200D\uFEFF]/g, "")
      .replace(/\s{3,}/g, " ")
      .trim();

  // ===== GET: 목록 (페이지네이션) =====
  if (method === "GET") {
    const page = parseInt(url.searchParams.get("page") || "1", 10);
    const limit = parseInt(url.searchParams.get("limit") || "20", 10);
    const MAX_LIMIT = 50;
    const safeLimit = Math.max(1, Math.min(limit, MAX_LIMIT));

    const idx = JSON.parse((await COMMENTS.get("idx")) || "[]");
    const total = idx.length;
    const totalPages = Math.ceil(total / safeLimit) || 1;
    const curPage = Math.max(1, Math.min(page, totalPages));

    const start = Math.max(0, total - curPage * safeLimit);
    const end = total - (curPage - 1) * safeLimit;
    const slice = idx.slice(start, end);

    const items = [];
    for (const id of slice) {
      const raw = await COMMENTS.get(`c:${id}`);
      if (raw) items.push(JSON.parse(raw));
    }

    return json({ total, page: curPage, limit: safeLimit, items });
  }

  // ===== POST: 작성 =====
  if (method === "POST") {
    if (!/application\/json/i.test(request.headers.get("content-type") || "")) {
      return json({ error: "INVALID_CONTENT_TYPE" }, 415);
    }
    const data = await request.json().catch(() => ({}));
    let text = sanitize(data.text || "");

    const MAX_LEN = 300; // 길이 제한(서버 강제)
    if (!text) return json({ error: "내용이 비었습니다." }, 400);
    if (text.length > MAX_LEN) return json({ error: `댓글은 ${MAX_LEN}자 이내로 제한됩니다.` }, 400);

    const who = await ipHash(request);

    // 1인 1회 작성 제한
    const used = await COMMENTS.get(`by:${who}`);
    if (used) return json({ error: "이미 작성하셨습니다. (1인 1회)" }, 409);

    const idx = JSON.parse((await COMMENTS.get("idx")) || "[]");
    const nextId = idx.length ? Math.max(...idx) + 1 : 1;

    const item = { id: nextId, by: `탈출자 ${nextId}`, text, ts: Date.now() };
    idx.push(nextId);

    await COMMENTS.put("idx", JSON.stringify(idx));
    await COMMENTS.put(`c:${nextId}`, JSON.stringify(item));
    await COMMENTS.put(`by:${who}`, String(nextId), { expirationTtl: 60 * 60 * 24 * 365 });

    return json({ ok: true, item });
  }

  // ===== DELETE: 운영자 삭제 =====
  if (method === "DELETE") {
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (!OWNER_PASSWORD || token !== OWNER_PASSWORD) return json({ error: "FORBIDDEN" }, 403);

    const data = await request.json().catch(() => ({}));
    const id = parseInt(data.id, 10);
    if (!id) return json({ error: "INVALID_ID" }, 400);

    const idx = JSON.parse((await COMMENTS.get("idx")) || "[]");
    const pos = idx.indexOf(id);
    if (pos === -1) return json({ error: "NOT_FOUND" }, 404);

    idx.splice(pos, 1);
    await COMMENTS.put("idx", JSON.stringify(idx));
    await COMMENTS.delete(`c:${id}`);

    return json({ ok: true });
  }

  return json({ error: "Method Not Allowed" }, 405);
}
