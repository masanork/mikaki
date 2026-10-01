/// <reference path="./worker-configuration.d.ts" />
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/oidc/native/callback') {
      if (request.method !== 'GET') return new Response('Not found', { status: 404 });
      // Drop the entire query: never expose or forward an authorization code/state.
      return new Response(null, {
        status: 303,
        headers: {
          Location: '/native-link-help',
          'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer',
        },
      });
    }
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
