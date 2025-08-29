export async function onRequest({ request, env, next }) {
  const url = new URL(request.url);
  if (url.pathname.startsWith('/secret')) {
    const cookie = request.headers.get('Cookie') || '';
    if (!cookie.includes('auth=ok')) {
      return new Response('Unauthorized', { status: 302, headers: { 'Location': '/' } });
    }
  }
  return next();
}
