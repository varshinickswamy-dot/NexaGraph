// =====================================================
// NEXAGRAPH AI - SHARED AUTHENTICATED API CLIENT
// =====================================================

export const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8000";

const AUTH_TOKEN_KEY = "nexagraph-access-token";

// =====================================================
// AUTHENTICATED FETCH
// =====================================================

export async function authenticatedFetch(
  path: string,
  options: RequestInit = {}
): Promise<Response> {

  const headers = new Headers(options.headers);

  const token = window.localStorage.getItem(AUTH_TOKEN_KEY);

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });
}