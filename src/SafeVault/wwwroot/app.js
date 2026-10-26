// Client-side validation is only a convenience; the server re-validates everything.
// Output is written with textContent (never innerHTML) so server data cannot inject markup.
let token = null; // kept in memory only, not in localStorage

const output = document.getElementById("output");
const show = (text) => { output.textContent = text; };

async function post(url, form) {
  const body = Object.fromEntries(new FormData(form));
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const { status, data } = await post("/api/auth/register", e.target);
  show(`${status}: ${data.message ?? data.error ?? ""}`);
});

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const { status, data } = await post("/api/auth/login", e.target);
  token = data.token ?? null;
  show(token ? "Logged in." : `${status}: ${data.error ?? "Login failed"}`);
});

document.getElementById("whoami").addEventListener("click", async () => {
  if (!token) return show("Not logged in.");
  const res = await fetch("/api/vault/me", { headers: { Authorization: `Bearer ${token}` } });
  show(`${res.status}: ${JSON.stringify(await res.json().catch(() => ({})))}`);
});
