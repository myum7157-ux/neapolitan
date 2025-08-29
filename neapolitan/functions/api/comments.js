// KV 바인딩: env.COMMENTS
// 운영자 비번: env.OWNER_PASSWORD
// 구조:
// idx = JSON 배열 [id1,id2,...] (코멘트 순서)
// comments:<id> = JSON { id, text, by, at }
// by:<ipHash> = <id> (1인 1회 방지)

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  // 유틸: 해시 (IP 보호용)
  async function sha256(s) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,"0")).join("");
  }
  async function ipHash(req) {
    const ip = req.headers.get("cf-connecting-ip") || "0.0.0.0";
    return await sha256(ip + (env.SECRET_SALT || "salt"));
  }

  // 리스트 조회
  if (method === "GET") {
    const idxRaw = await env.COMMENTS.get("idx");
    if (!idxRaw) return new Response("[]", { headers: { "Content-Type": "application/json" }});
    const idx = JSON.parse(idxRaw);
    const out = [];
    for (let id of idx) {
      const c = await env.COMMENTS.get("comments:" + id);
      if (c) out.push(JSON.parse(c));
    }
    return new Response(JSON.stringify(out), { headers: { "Content-Type": "application/json" }});
  }

  // 코멘트 작성
  if (method === "POST") {
    const ip = await ipHash(request);
    const body = await request.json().catch(() => ({}));
    const text = (body.text || "").trim();

    if (!text) return new Response(JSON.stringify({ error:"내용이 비어있습니다."}), { status:400 });

    // 중복 방지 (한 번만 작성 가능)
    const prev = await env.COMMENTS.get("by:" + ip);
    if (prev) {
      return new Response(JSON.stringify({ error:"이미 코멘트를 작성했습니다."}), { status:403 });
    }

    // 신규 ID
    let idxRaw = await env.COMMENTS.get("idx");
    let idx = idxRaw ? JSON.parse(idxRaw) : [];
    const newId = idx.length + 1;
    const entry = {
      id: newId,
      text,
      by: "탈출자 " + newId,
      at: Date.now()
    };

    // 저장
    idx.push(newId);
    await env.COMMENTS.put("idx", JSON.stringify(idx));
    await env.COMMENTS.put("comments:" + newId, JSON.stringify(entry));
    await env.COMMENTS.put("by:" + ip, String(newId));

    return new Response(JSON.stringify(entry), { headers: { "Content-Type": "application/json" }});
  }

  // 코멘트 삭제 (운영자만 가능)
  if (method === "DELETE") {
    const auth = request.headers.get("Authorization") || "";
    if (auth !== "Bearer " + env.OWNER_PASSWORD) {
      return new Response("권한 없음", { status:403 });
    }

    const { id } = await request.json().catch(()=>({}));
    if (!id) return new Response("잘못된 요청", { status:400 });

    // idx에서 빼고 다시 채우기
    let idxRaw = await env.COMMENTS.get("idx");
    let idx = idxRaw ? JSON.parse(idxRaw) : [];
    idx = idx.filter(x => x !== id);

    // ID 리셋 (1부터 다시 이어지도록)
    const comments = [];
    for (let newId = 0; newId < idx.length; newId++) {
      const c = await env.COMMENTS.get("comments:" + idx[newId]);
      if (c) {
        const parsed = JSON.parse(c);
        parsed.id = newId + 1;
        parsed.by = "탈출자 " + (newId + 1);
        comments.push(parsed);
      }
    }

    // 저장 리셋
    await env.COMMENTS.delete("idx");
    await env.COMMENTS.put("idx", JSON.stringify(comments.map(c=>c.id)));
    for (let c of comments) {
      await env.COMMENTS.put("comments:" + c.id, JSON.stringify(c));
    }

    return new Response(JSON.stringify({ ok:true }), { headers: { "Content-Type": "application/json" }});
  }

  return new Response("Method Not Allowed", { status:405 });
}
