export async function onRequestPost({ request, env }) {
  const formData = await request.formData();
  const pw = formData.get('password')?.toString() ?? '';

  if (pw === env.PASSWORD) {
    return new Response(null, {
      status: 302,
      headers: {
        'Set-Cookie': `auth=ok; Path=/; HttpOnly; Secure; Max-Age=86400; SameSite=Lax`,
        'Location': '/secret/'
      }
    });
  }
  return new Response(null, { status: 302, headers: { 'Location': '/?err=1' } });
}