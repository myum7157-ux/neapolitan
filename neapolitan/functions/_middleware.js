export const onRequest = [
  async ({ request, next }) => {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/secret')) {
      const cookie = request.headers.get('Cookie') || '';
      const hasAuth = /(?:^|;\s*)auth=ok(?:;|$)/.test(cookie);
      if (!hasAuth) {
        return new Response(null, { status: 302, headers: { Location: '/' } });
      }
    }
    return next();
  }
];
