/**
 * Sidebar INT (internal / partner) gate. Runs at Cloudflare's edge BEFORE any page under
 * /projects/Sidebar/INT/ is served, so a locked page never reaches the browser
 * and crawlers get nothing to index.
 *
 * Same technique as the VCR gate on adamandroid.com, deliberately much smaller:
 * one password, one cookie, no client scopes, no owner override, no JSON
 * endpoint. Those exist on .com because that site serves many clients. This
 * one serves two people.
 *
 * Secrets live in Cloudflare Pages > Settings > Environment variables, never in git:
 *   SIDEBAR_SECRET  random string, signs the cookie (HMAC-SHA256)
 *   SIDEBAR_INT_PW  sha256 of the INT password
 *
 * Hash a password with:
 *   printf '%s' 'thepassword' | shasum -a 256
 *
 * Two-key design:
 *   SIDEBAR_INT_PW   opens INT, and will also open EXT. The internal key.
 *   SIDEBAR_EXT_PW   opens EXT only. The client key.
 *
 * Adding EXT later: copy this file to functions/projects/Sidebar/EXT/, set
 * BASE to /projects/Sidebar/EXT, COOKIE to "sb_ext", COOKIE_PATH to
 * "/projects/Sidebar/EXT/", the HMAC label to "sidebar-ext", and have it
 * accept EITHER SIDEBAR_EXT_PW or SIDEBAR_INT_PW on POST, and accept EITHER
 * an sb_ext or a valid sb_int cookie on GET. Both gates share SIDEBAR_SECRET
 * for signing only. Signing is not granting: INT opens EXT because the EXT
 * gate is written to honour it, not because the secret is shared.
 *
 * Note on CSS: the gate inlines its own styles. The page it protects loads
 * sidebar-style.css from /projects/Sidebar/, which sits OUTSIDE this gate, so
 * that file is not affected either way. The lock art is at /assets/lock.png,
 * also outside, so it always loads.
 */

const BASE = "/projects/Sidebar/INT";
const COOKIE = "sb_int";
/** INT is the master key: its cookie is scoped to the parent so it also
    satisfies a future EXT gate. EXT will set sb_ext scoped to EXT only. */
const COOKIE_PATH = "/projects/Sidebar/";
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

/** Constant-time compare. A length check leaks nothing useful here. */
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

async function valid(env, token) {
  if (!token) return false;
  const [exp, sig] = token.split(".");
  if (!exp || !sig) return false;
  if (Date.now() > Number(exp)) return false;
  return timingSafe(sig, await sign(env.SIDEBAR_SECRET, "sidebar-int|" + exp));
}

async function grant(env, days) {
  const exp = Date.now() + days * 864e5;
  return exp + "." + await sign(env.SIDEBAR_SECRET, "sidebar-int|" + exp);
}

/**
 * The lock page. The whole screen is the padlock: a thin header, the artwork
 * centred in the space that is left, the password field drawn as a fourth bar
 * continuing the lock body, and the footer against the bottom of the window.
 * No prose. The lock is the instruction.
 *
 * Bar geometry is measured from the 600x600 artwork, not guessed:
 *   bars span    x 40 to 560 of 600  =  86.667% wide
 *   bar height           74 / 600    =  12.333%
 *   gap between bars     23 / 600    =   3.833%
 *   last bar ends y 594, art is 600  =   6/600 slack at the bottom
 * so the input's margin-top is (23 - 6) / 600 = 2.833%. Everything is
 * expressed against one --lock width, so the fourth bar stays aligned at
 * any size including the mobile step-down.
 */
function gate(msg) {
  return new Response(`<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AdamAndroid.ai</title>
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
  <span class="proj">PROJECT &middot; SIDEBAR &middot; INT</span>
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
    // 200, not 401. A password wall is a PAGE, not an API error, and every
    // link-preview bot (iMessage, Slack, WhatsApp) refuses to render a card for
    // a non-200. Nothing about access changes: the content is still not served,
    // and the noindex meta and headers keep search engines out.
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

  // Fails closed. A half-configured deploy shows the lock, never the content.
  if (!env.SIDEBAR_SECRET || !env.SIDEBAR_INT_PW) {
    return gate("Access is not configured yet.");
  }

  // Password submitted from the gate.
  if (request.method === "POST") {
    const form = await request.formData();
    const h = await sha256(form.get("pw") || "");
    if (!timingSafe(h, env.SIDEBAR_INT_PW)) {
      return gate("That password was not recognised.");
    }
    const hh = new Headers({ "Location": path, "Cache-Control": "no-store" });
    // Path is the PARENT, /projects/Sidebar/, not BASE. A browser only sends a
    // cookie to paths at or below its Path, so scoping this to INT would make
    // it invisible to a future EXT gate and INT could never open EXT.
    hh.append("Set-Cookie",
      `${COOKIE}=${await grant(env, 30)}` +
      `; Path=${COOKIE_PATH}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
    return new Response(null, { status: 303, headers: hh });
  }

  // Already unlocked. Serve the real page, but never let it be cached or indexed.
  if (await valid(env, cookies(request)[COOKIE])) {
    const res = await next();
    const out = new Response(res.body, res);
    out.headers.set("Cache-Control", "private, no-store, max-age=0");
    out.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex");
    out.headers.set("Referrer-Policy", "no-referrer");
    return out;
  }

  // Locked. A made-up path under BASE gets this identical gate, so probing
  // cannot reveal whether a project exists.
  return gate();
}
