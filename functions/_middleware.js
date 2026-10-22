/**
 * AdamAndroid.ai site-wide access gate. ONE root middleware runs at Cloudflare's
 * edge BEFORE any page is served. It protects ANY folder listed in AAAI_KEYS, so a
 * new folder is locked from the terminal (set_password.py) with no new file and no
 * code change — the generator just adds the scope to AAAI_KEYS and redeploys.
 *
 * Modeled on the VCR gate at adamandroid.com/WeSpeak/Camera/VCR, generalized from a
 * single fixed BASE to the whole site, and dressed in the existing .ai padlock visual
 * (lock art + the fourth-bar password field + eye toggle, dark/orange).
 *
 * Secrets live in Cloudflare Pages > Settings > Environment variables, never in git:
 *   AAAI_SECRET  random string, signs the cookies (HMAC-SHA256)
 *   AAAI_OWNER   sha256 of Adam's master password        -> opens everything
 *   AAAI_KEYS    {"projects/Sidebar":"<sha>", ...}        -> scope -> password hash
 *   AAAI_NAMES   {"projects/Sidebar":"Sidebar", ...}      -> scope -> gate card label
 *
 * Scope = a site-root-relative folder path. A password set at "projects/Sidebar"
 * opens everything under /projects/Sidebar/. A password set at
 * "projects/Sidebar/INT" opens only that subfolder. Longest match names the card,
 * but ANY protected ancestor also grants, so a parent password keeps working when a
 * child gets its own.
 *
 * Properties carried over from the VCR gate, intact:
 *   - unprotected paths pass straight through (next()); only AAAI_KEYS scopes gate,
 *     so a bug here can never lock the public site Adam has not locked.
 *   - cookies are HMAC-signed and bound to their scope name; Path-scoped so a parent
 *     cascades down.
 *   - timing-safe compare, sha256 hashing.
 *   - 200 gate page (not 401) so link-preview bots still render the generic share
 *     card instead of leaking; noindex + no-store + no-referrer + nosniff headers.
 *   - fails CLOSED: a protected path with a half-configured deploy shows the lock.
 *   - no existence leak: a made-up path under a protected scope returns the IDENTICAL
 *     gate, because gating is by folder prefix, never by whether a file exists.
 */

const enc = new TextEncoder();

async function sha256(s) {
  const b = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
async function sign(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const s = await crypto.subtle.sign("HMAC", k, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(s)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function timingSafe(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function cookies(req) {
  const out = {};
  (req.headers.get("Cookie") || "").split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
/** "projects/Sidebar" -> "aaai_projects_Sidebar"; cookie names allow a narrow charset. */
function cookieName(scope) {
  return "aaai_" + scope.replace(/[^A-Za-z0-9]/g, "_");
}
/**
 * Every folder-prefix of a path, longest first. The trailing filename segment
 * (anything containing a ".") is dropped so a file is gated by its folder, not
 * treated as its own scope.
 *   "/projects/Sidebar/INT/x.html" -> ["projects/Sidebar/INT","projects/Sidebar","projects"]
 */
function scopeChain(path) {
  const parts = path.split("/").filter(Boolean);
  if (parts.length && parts[parts.length - 1].includes(".")) parts.pop();
  const out = [];
  for (let i = parts.length; i > 0; i--) out.push(parts.slice(0, i).join("/"));
  return out;
}

async function valid(env, name, token) {
  if (!token) return false;
  const [exp, sig] = token.split(".");
  if (!exp || !sig) return false;
  if (Date.now() > Number(exp)) return false;
  return timingSafe(sig, await sign(env.AAAI_SECRET, name + "|" + exp));
}
async function grant(env, name, days) {
  const exp = Date.now() + days * 864e5;
  return exp + "." + await sign(env.AAAI_SECRET, name + "|" + exp);
}

/**
 * The lock page — the .ai padlock visual, byte-for-byte the styling of the existing
 * Sidebar/INT gate: a thin header, the 600x600 lock artwork centred, the password
 * field drawn as a fourth bar continuing the lock body, eye toggle, footer. No prose:
 * the lock is the instruction. The scope label rides in <title>, the sr-only heading
 * and the muted header tag; the OG/Twitter tags stay generic so a pasted link never
 * leaks a folder name into a room Adam does not control.
 */
function gate(label, msg) {
  const L = label || "Protected";
  return new Response(`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${L} &middot; AdamAndroid.ai</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<!-- A link preview of a gated page fetches THIS page, not the content, so the
     share tags live here. They are deliberately generic: pasting a link into a
     thread cannot leak a client or project name into a room Adam does not control. -->
<meta property="og:type" content="website">
<meta property="og:title" content="AdamAndroid.ai">
<meta property="og:description" content="Password protected.">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="AdamAndroid.ai">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
<meta name="referrer" content="no-referrer">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080808; --surface:#0f0f0f; --border:#1e1e1e;
  --text:#e2e2e2; --dim:#555; --acc:#FF9900; --acc2:#FF6600;
  --mono:'Space Mono',ui-monospace,monospace;
  --sans:'Syne',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box}
body{
  margin:0; min-height:100vh; min-height:100dvh;
  display:flex; flex-direction:column;
  background:var(--bg); color:var(--text);
  font-family:var(--sans); -webkit-font-smoothing:antialiased;
}
/* --- header --- */
.topbar{flex:0 0 auto; border-bottom:1px solid var(--border); background:rgba(8,8,8,.93)}
.topbar-in{
  max-width:1240px; margin:0 auto; padding:11px 24px;
  display:flex; align-items:center; gap:14px;
}
.logo{
  font-family:var(--mono); font-size:12px; font-weight:700;
  letter-spacing:.18em; color:var(--acc);
}
.proj{font-family:var(--mono); font-size:10px; letter-spacing:.16em; color:var(--dim)}
/* --- the lock --- */
.gate-main{
  flex:1 1 auto; display:flex; align-items:center; justify-content:center;
  padding:40px 20px;
}
.lock{
  --lock:300px;
  --bar-w:86.667%;
  --bar-h:calc(var(--lock) * .12333);
  --bar-gap:calc(var(--lock) * .02833);
  width:var(--lock); max-width:100%; margin:0;
  display:flex; flex-direction:column; align-items:center;
}
.lock-art{display:block; width:100%; height:auto; user-select:none; -webkit-user-drag:none}
.sr-only{
  position:absolute; width:1px; height:1px; padding:0; margin:-1px;
  overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap; border:0;
}
/* the fourth bar. targets input[name=pw], NOT input[type=password]: the eye
   toggle flips the type to text, and a type-based selector stops matching the
   instant it does, turning the styled bar into a native white box mid-typing. */
.bar{position:relative; width:var(--bar-w); margin:var(--bar-gap) 0 0}
input[name="pw"]{
  display:block; width:100%; height:var(--bar-h); margin:0;
  padding:0 calc(var(--bar-h) * .9);
  background:var(--bg); border:1px solid var(--acc); border-radius:0;
  color:var(--acc); font-family:var(--mono);
  font-size:calc(var(--lock) * .052); letter-spacing:.22em;
  text-align:center; text-indent:.22em;
  transition:box-shadow .12s ease, border-color .12s ease;
}
input[name="pw"]::placeholder{color:#6a6a6a; opacity:1; transition:color .12s ease}
input[name="pw"]:focus::placeholder{color:transparent}
input[name="pw"]:focus{outline:none; box-shadow:0 0 0 2px rgba(255,153,0,.22)}
/* Safari and Chromium draw their own key / autofill button at the right edge,
   exactly where the arrow lives. Native shadow DOM, so removed rather than
   worked around. A password manager EXTENSION injects its own icon instead,
   which no page stylesheet can touch. */
input[name="pw"]::-webkit-credentials-auto-fill-button,
input[name="pw"]::-webkit-strong-password-auto-fill-button,
input[name="pw"]::-webkit-strong-password-viewer-button,
input[name="pw"]::-webkit-contacts-auto-fill-button,
input[name="pw"]::-webkit-caps-lock-indicator,
input[name="pw"]::-webkit-textfield-decoration-container{
  display:none!important; visibility:hidden!important; pointer-events:none!important;
  width:0!important; height:0!important; margin:0!important; opacity:0!important;
}
.go,.eye{
  position:absolute; top:50%; transform:translateY(-50%);
  display:flex; align-items:center; justify-content:center;
  padding:0; border:0; background:none; color:var(--acc);
  cursor:pointer; opacity:.5; transition:opacity .12s ease;
}
.go{right:calc(var(--bar-h) * .24); width:calc(var(--bar-h) * .58); height:calc(var(--bar-h) * .58)}
.eye{left:calc(var(--bar-h) * .24); width:calc(var(--bar-h) * .60); height:calc(var(--bar-h) * .60)}
.go svg,.eye svg{width:100%; height:100%; display:block}
.bar:focus-within .go,.bar:focus-within .eye,.go:hover,.eye:hover{opacity:1}
.go:focus-visible,.eye:focus-visible{opacity:1; outline:1px solid var(--acc); outline-offset:3px}
.eye .e-shut{opacity:1}
.eye.on .e-shut{opacity:0}
/* message line. keeps its height so the lock does not jump on a wrong password */
.m{
  min-height:1.2em; margin-top:calc(var(--lock) * .05);
  font-family:var(--mono); font-size:11px; letter-spacing:.12em;
  text-transform:uppercase; text-align:center; color:var(--acc2);
}
/* --- footer --- */
.foot{
  flex:0 0 auto; margin-top:auto; border-top:1px solid var(--border);
  padding:24px; display:flex; align-items:center; justify-content:space-between;
  max-width:1240px; width:100%; margin-left:auto; margin-right:auto;
}
.foot-name{font-size:13px; font-weight:600; color:var(--dim)}
.foot-name .ai{color:var(--acc)}
.foot small{font-size:12px; color:var(--dim)}
@media (max-width:640px){
  .foot{flex-direction:column; gap:12px; text-align:center}
  .lock{--lock:240px}
  .gate-main{padding:28px 16px}
}
@media (max-height:620px){ .lock{--lock:220px} .gate-main{padding:20px} }
</style>
</head><body>

<div class="topbar"><div class="topbar-in">
  <span class="logo">ADAMOS</span>
  <span class="proj">${L}</span>
</div></div>

<main class="gate-main">
<form class="lock" method="POST">
  <h1 class="sr-only">Password required</h1>
  <img class="lock-art" src="/assets/lock.png" alt="" width="600" height="600">
  <div class="bar">
    <button type="button" class="eye" aria-label="Show password" aria-pressed="false">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"
           stroke-linecap="round" stroke-linejoin="round"><path class="e-open" d="M1.5 12S5 5.5 12 5.5 22.5 12 22.5 12 19 18.5 12 18.5 1.5 12 1.5 12z"/><circle class="e-open" cx="12" cy="12" r="3.2"/><path class="e-shut" d="M3 3l18 18"/></svg>
    </button>
    <input type="password" name="pw" placeholder="ENTER &middot; PASS"
           autocomplete="current-password" aria-label="Password">
    <button type="submit" class="go" aria-label="Unlock">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"
           stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h13"/><path d="M12 6l6 6-6 6"/></svg>
    </button>
  </div>
  <div class="m">${msg || ""}</div>
</form>
</main>

<footer class="foot">
  <span class="foot-name">AdamAndroid<span class="ai">.ai</span></span>
  <small>&copy; 2026 AdamAndroid.ai &middot; Help Humans, Ride Robots*</small>
</footer>

<script>
(function(){
  var f=document.querySelector('.lock'); if(!f) return;
  var i=f.querySelector('input[name=pw]'), b=f.querySelector('.eye');
  if(!i||!b) return;
  b.addEventListener('click',function(){
    var shown = i.getAttribute('type')==='text';
    i.setAttribute('type', shown ? 'password' : 'text');
    b.setAttribute('aria-pressed', shown ? 'false' : 'true');
    b.setAttribute('aria-label', shown ? 'Show password' : 'Hide password');
    b.classList.toggle('on', !shown);
    i.focus();
  });
})();
</script>
</body></html>`, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "private, no-store, max-age=0",
      "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet, noimageindex",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const path = new URL(request.url).pathname;

  let keys = {}, names = {};
  try { keys = JSON.parse(env.AAAI_KEYS || "{}"); } catch (e) { keys = {}; }
  try { names = JSON.parse(env.AAAI_NAMES || "{}"); } catch (e) { names = {}; }

  // Which protected scopes is this path inside? Longest first.
  const guards = scopeChain(path).filter(s => Object.prototype.hasOwnProperty.call(keys, s));

  // Not under any locked folder: serve normally. A root middleware must be
  // invisible everywhere Adam has not explicitly locked.
  if (guards.length === 0) return next();

  const label = names[guards[0]] || names[guards[guards.length - 1]] || "Protected";

  // Fails closed: cannot verify a cookie without the signing secret.
  if (!env.AAAI_SECRET) return gate(label, "Access is not configured yet.");

  // Password submitted from the gate form.
  if (request.method === "POST") {
    const form = await request.formData();
    const h = await sha256(form.get("pw") || "");
    const owner = !!(env.AAAI_OWNER && timingSafe(h, env.AAAI_OWNER));
    const match = owner ? null : guards.find(s => timingSafe(h, keys[s]));
    if (!owner && !match) return gate(label, "That password was not recognised.");
    const name = owner ? "owner" : match;
    const cn = owner ? "aaai_owner" : cookieName(match);
    const cpath = owner ? "/" : "/" + match + "/";
    const hh = new Headers({ "Location": path, "Cache-Control": "no-store" });
    hh.append("Set-Cookie", `${cn}=${await grant(env, name, 30)}` +
      `; Path=${cpath}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
    return new Response(null, { status: 303, headers: hh });
  }

  // GET: owner cookie, or a valid cookie for any protected ancestor, grants.
  const jar = cookies(request);
  let ok = await valid(env, "owner", jar["aaai_owner"]);
  if (!ok) {
    for (const s of guards) {
      if (await valid(env, s, jar[cookieName(s)])) { ok = true; break; }
    }
  }
  if (ok) {
    const res = await next();
    const out = new Response(res.body, res);
    out.headers.set("Cache-Control", "private, no-store, max-age=0");
    out.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex");
    out.headers.set("Referrer-Policy", "no-referrer");
    out.headers.set("X-Content-Type-Options", "nosniff");
    return out;
  }

  // Locked. A made-up path under a protected scope gets this identical gate.
  return gate(label);
}
