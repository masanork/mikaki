export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (
      request.method === 'GET' &&
      /^\/internal\/recipient-keys\/[A-Za-z0-9_-]{43}\/verify$/.test(url.pathname)
    ) {
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 404 });
  },
};
