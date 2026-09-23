// Local-only probe entry point. No login, signing, or database endpoints.
export default {
  fetch() {
    return new Response("Local design probe; no public API", { status: 404 });
  }
};
