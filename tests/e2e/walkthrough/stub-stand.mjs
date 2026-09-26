// Card U-2 test infrastructure: a dummy stand for the walkthrough tests.
//
// It reproduces only what the walkthrough touches: the application's sign-in
// link, an identity-provider redirect with a Keycloak-shaped form, and enough
// of the Sources, Settings and Search screens for the read-only scenario. It is
// never used by the product and never by a real stand run.
//
// The server records every sign-in attempt and whether the confirmation or save
// controls were pressed, so a test can prove the read-only scenario really did
// not touch them.

import http from "node:http";
import { once } from "node:events";

function appHTML() {
  return `<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>Stub stand</title></head>
<body>
<header id="stand-header">
  <span id="stand-clock"></span>
  <span id="stand-observed" class="mono"></span>
</header>
<nav class="rail">
  <button aria-label="Sources" id="nav-sources" type="button">Sources</button>
  <button aria-label="Settings" id="nav-settings" type="button">Settings</button>
  <button aria-label="Search" id="nav-search" type="button">Search</button>
</nav>
<main>
  <section id="view-sources" hidden>
    <h2>Sources</h2>
    <ul class="source-rows"><li class="source-row">Договоры</li></ul>
    <div class="source-confirm-batch" role="group" aria-label="Confirm tables awaiting confirmation">
      <button class="primary-button source-confirm-batch-action" id="confirm" type="button">Confirm tables</button>
    </div>
  </section>
  <section id="view-settings" hidden>
    <header class="model-context-head"><h2>Workspace model context</h2>
      <button class="primary-button" id="save" type="button">Save all</button>
    </header>
    <section id="model-context-panel-description">
      <textarea id="model-context-description" maxlength="2000">Синтетический контекст стенда</textarea>
    </section>
  </section>
  <section id="view-search">
    <form class="question-composer" id="composer">
      <textarea id="ask-question" aria-label="Question"></textarea>
      <button aria-label="Ask" class="go" type="submit">Ask</button>
    </form>
    <div id="turns"></div>
    <aside aria-label="Answer evidence" class="evi" hidden>
      <header class="evi-h"><span>extracted text · observed 2026-01-01T00:00:00Z</span></header>
    </aside>
  </section>
</main>
<script>
  // Card U-3 return 1: the same two shapes of wall-clock reading the real
  // product renders — its one date formatter and a raw ISO timestamp. They are
  // produced in the page from the browser's own clock, so a test can run this
  // stand on two different days by pinning the browser clock.
  function standFormatClock(date) {
    return date.toLocaleString("en-US", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  }
  document.getElementById("stand-clock").textContent = standFormatClock(new Date());
  document.getElementById("stand-observed").textContent = new Date().toISOString();
  const views = { sources: document.getElementById("view-sources"), settings: document.getElementById("view-settings"), search: document.getElementById("view-search") };
  function show(name) { for (const [key, node] of Object.entries(views)) node.hidden = key !== name; }
  document.getElementById("nav-sources").addEventListener("click", () => show("sources"));
  document.getElementById("nav-settings").addEventListener("click", () => show("settings"));
  document.getElementById("nav-search").addEventListener("click", () => show("search"));
  document.getElementById("confirm").addEventListener("click", () => { void fetch("/__stub/confirm", { method: "POST" }); });
  document.getElementById("save").addEventListener("click", () => { void fetch("/__stub/save", { method: "POST" }); });
  const turns = document.getElementById("turns");
  document.getElementById("composer").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = document.getElementById("ask-question");
    const question = input.value.trim();
    if (question === "") return;
    input.value = "";
    const article = document.createElement("article");
    article.className = "turn";
    const heading = document.createElement("p");
    heading.className = "turn-question";
    heading.textContent = "Question" + question;
    const body = document.createElement("div");
    body.className = "answer-body";
    body.textContent = "Ответ стенда на вопрос: " + question;
    if (turns.children.length === 0) {
      const mark = document.createElement("button");
      mark.className = "fn";
      mark.type = "button";
      mark.textContent = "1";
      mark.addEventListener("click", () => { document.querySelector("aside.evi").hidden = false; });
      body.appendChild(mark);
    }
    article.appendChild(heading);
    article.appendChild(body);
    turns.appendChild(article);
  });
</script>
</body>
</html>`;
}

function loginHTML(error) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign in to KnowVault</title></head>
<body>
${error ? '<p id="input-error" role="alert">Invalid username or password.</p>' : ""}
<form id="kc-form-login" method="post" action="/idp/authenticate">
  <input id="username" name="username" type="text" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button name="login" id="kc-login" type="submit">Sign in</button>
</form>
</body>
</html>`;
}

function landingHTML() {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>KnowVault</title></head>
<body><a href="/auth/login">Sign in</a></body>
</html>`;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

export async function startStubStand(options = {}) {
  const username = options.username ?? "stub-user";
  const password = options.password ?? "stub-password";
  const state = { authenticated: 0, failedLogins: 0, confirmClicks: 0, saveClicks: 0, writes: [] };

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://stub.invalid");
    if (request.method !== "GET" && request.method !== "HEAD") {
      state.writes.push(`${request.method} ${url.pathname}`);
    }
    const authenticated = (request.headers.cookie ?? "").split(/;\s*/).includes("session=ok");
    const send = (status, type, body) => {
      response.writeHead(status, { "content-type": type, "cache-control": "no-store" });
      response.end(request.method === "HEAD" ? undefined : body);
    };

    if (url.pathname === "/__stub/confirm" && request.method === "POST") {
      state.confirmClicks += 1;
      return send(204, "text/plain", "");
    }
    if (url.pathname === "/__stub/save" && request.method === "POST") {
      state.saveClicks += 1;
      return send(204, "text/plain", "");
    }
    if (url.pathname === "/" || url.pathname === "/index.html") {
      if (authenticated) return send(200, "text/html; charset=utf-8", appHTML());
      return send(200, "text/html; charset=utf-8", landingHTML());
    }
    if (url.pathname === "/auth/login") {
      response.writeHead(303, { location: "/idp/login", "cache-control": "no-store" });
      return response.end();
    }
    if (url.pathname === "/idp/login") {
      return send(200, "text/html; charset=utf-8", loginHTML(url.searchParams.has("error")));
    }
    if (url.pathname === "/idp/authenticate" && request.method === "POST") {
      const form = new URLSearchParams(await readBody(request));
      if (form.get("username") === username && form.get("password") === password) {
        state.authenticated += 1;
        response.writeHead(303, {
          location: "/",
          "set-cookie": "session=ok; Path=/; HttpOnly; SameSite=Lax",
          "cache-control": "no-store",
        });
        return response.end();
      }
      state.failedLogins += 1;
      response.writeHead(303, { location: "/idp/login?error=1", "cache-control": "no-store" });
      return response.end();
    }
    return send(404, "text/plain; charset=utf-8", "not found");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    server,
    baseURL: `http://127.0.0.1:${server.address().port}`,
    username,
    password,
    state,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
