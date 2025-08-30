// KV 바인딩: env.COMMENTS
// 환경변수: env.OWNER_PASSWORD (운영자 토큰), env.SECRET_SALT (선택: IP 해시 강화)

export async function onRequest({ request, env }) {
  const { COMMENTS, OWNER_PASSWORD = "", SECRET_SALT = "" } = env;
  const method = request.method.toUpperCase();

  // ---- utils ----
  const json = (obj, status=200, headers={}) =>
    new Response(JSON.stringify(obj), { status, headers: { "Content-Type":"application/json", ...headers } });

  const sha256 = async (s) => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("");
  };

  const ipHash = async () => {
    const ip = request.headers.get("cf-connecting-ip")
        || request.headers.get("CF-Connecting-IP")
        || "0.0.0.0";
    return await sha256(SECRET_SALT + "|" + ip);
  };

  const getIdx = async () => JSON.parse(await COMMENTS.get("idx") || "[]");
  const putIdx = (arr) => COMMENTS.put("idx", JSON.stringify(arr));

  // ---- routes ----
  if (method === "GET") {
    const idx = await getIdx();
    const out = [];
    for (const id of idx) {
      const raw = await COMMENTS.get(`c:${id}`);
      if (!raw) continue;
      const c = JSON.parse(raw);
      out.push({ id: c.id, text: c.text, ts: c.ts });
    }
    return json(out);
  }

  if (method === "POST") {
    const body = await request.json().catch(()=>null);
    const text = (body && String(body.text || "").trim()) || "";
    if (!text) return json({ error:"EMPTY" }, 400);

    // 운영자 토큰 → 무제한 작성 허용 (쿠키/1회제한 생략)
    const authHeader = (request.headers.get("Authorization") || "").trim();
    const adminToken = authHeader.replace(/^Bearer\s+/i, "").trim();
    const isAdminWriter = !!OWNER_PASSWORD && adminToken === OWNER_PASSWORD;

    if (!isAdminWriter) {
      // 일반 사용자는 로그인 쿠키 필요
      const cookie = request.headers.get("Cookie") || "";
      if (!/auth=ok/.test(cookie)) return json({ error:"UNAUTHORIZED" }, 401);

      // 일반 사용자는 1인 1회
      const who = await ipHash();
      const existId = await COMMENTS.get(`by:${who}`);
      if (existId) return json({ error:"ALREADY" }, 409);
    }

    const id = Date.now(); // 고유 ID
    const item = { id, text, ts: Date.now() };

    const idx = await getIdx();
    idx.push(id);

    await COMMENTS.put(`c:${id}`, JSON.stringify(item));
    if (!isAdminWriter) {
      const who = await ipHash();
      await COMMENTS.put(`by:${who}`, String(id));
      await COMMENTS.put(`who:${id}`, who);
    }
    await putIdx(idx);

    return json({ ok:true, id });
  }

  if (method === "DELETE") {
    // 운영자만
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (!OWNER_PASSWORD || token !== OWNER_PASSWORD) return json({ error:"FORBIDDEN" }, 403);

    const body = await request.json().catch(()=>null);
    const id = body && parseInt(body.id, 10);
    if (!id) return json({ error:"BAD_ID" }, 400);

    const idx = await getIdx();
    if (!idx.includes(id)) return json({ error:"NOT_FOUND" }, 404);

    // 지정한 id만 지움 (전체삭제 금지)
    const who = await COMMENTS.get(`who:${id}`);
    await COMMENTS.delete(`c:${id}`);
    if (who) {
      await COMMENTS.delete(`by:${who}`);
      await COMMENTS.delete(`who:${id}`);
    }
    const next = idx.filter(x => x !== id);
    await putIdx(next);

    return json({ ok:true, left: next.length });
  }

  return new Response("Method Not Allowed", { status:405, headers:{ "Allow":"GET, POST, DELETE" } });
}
