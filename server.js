/* Tech Sales Accelerator backend \u2014 one file, one dependency (stripe).
   Auth: passwordless magic links (HMAC-signed, 15-min expiry) \u2192 30-day session cookie.
   Payments: Stripe Checkout \u2192 webhook grants entitlements.
   Store: data/entitlements.json (swap getEntitlements/grantEntitlement for Postgres later).

   Env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, APP_SECRET, BASE_URL,
        PRICE_MOBILITY, PRICE_CITIES, PRICE_ENERGY, PRICE_BUNDLE, [PORT=3000]
*/
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const Stripe = require("stripe");

const ENV = (k, optional = false) => {
  const v = process.env[k];
  if (!v && !optional) { console.error(`Missing env: ${k}`); process.exit(1); }
  return v;
};
const stripe = new Stripe(ENV("STRIPE_SECRET_KEY"));
const WEBHOOK_SECRET = ENV("STRIPE_WEBHOOK_SECRET");
const APP_SECRET = ENV("APP_SECRET");
const BASE_URL = ENV("BASE_URL");
const PORT = process.env.PORT || 3000;

const PRICES = {
  mobility: ENV("PRICE_MOBILITY"),
  cities: ENV("PRICE_CITIES"),
  energy: ENV("PRICE_ENERGY"),
  bundle: ENV("PRICE_BUNDLE"),
  membership: ENV("PRICE_MEMBERSHIP"),
};
const SUBSCRIPTION_PRODUCTS = new Set(["membership"]);

/* ---------------- entitlement store (v1: JSON file, atomic writes) ---------------- */
const DATA_DIR = path.join(__dirname, "data");
const STORE = path.join(DATA_DIR, "entitlements.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(STORE)) fs.writeFileSync(STORE, "{}");

function readStore() { return JSON.parse(fs.readFileSync(STORE, "utf8")); }
function writeStore(obj) {
  const tmp = STORE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, STORE);
}
function getEntitlements(email) { return readStore()[email.toLowerCase()] || []; }
function grantEntitlement(email, product) {
  const db = readStore();
  const k = email.toLowerCase();
  db[k] = Array.from(new Set([...(db[k] || []), product]));
  writeStore(db);
  console.log(`granted ${product} \u2192 ${k}`);
}
function revokeEntitlement(email, product) {
  const db = readStore();
  const k = email.toLowerCase();
  db[k] = (db[k] || []).filter(p => p !== product);
  writeStore(db);
  console.log(`revoked ${product} \u2190 ${k}`);
}
/* subscription-id -> email map, so cancellations can revoke membership */
const SUBS = path.join(DATA_DIR, "subscriptions.json");
if (!fs.existsSync(SUBS)) fs.writeFileSync(SUBS, "{}");
function rememberSub(subId, email) {
  const m = JSON.parse(fs.readFileSync(SUBS, "utf8"));
  m[subId] = email.toLowerCase();
  fs.writeFileSync(SUBS, JSON.stringify(m, null, 2));
}
function emailForSub(subId) {
  return JSON.parse(fs.readFileSync(SUBS, "utf8"))[subId] || null;
}

/* ---------------- signing helpers (magic links + sessions) ---------------- */
const b64u = (buf) => Buffer.from(buf).toString("base64url");
function sign(payloadObj) {
  const payload = b64u(JSON.stringify(payloadObj));
  const sig = crypto.createHmac("sha256", APP_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function verify(token) {
  const [payload, sig] = String(token || "").split(".");
  if (!payload || !sig) return null;
  const expect = crypto.createHmac("sha256", APP_SECRET).update(payload).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  const obj = JSON.parse(Buffer.from(payload, "base64url").toString());
  if (obj.exp && Date.now() > obj.exp) return null;
  return obj;
}

/* ---------------- email via Resend ---------------- */
const RESEND_KEY = process.env.RESEND_KEY || "";
const EMAIL_FROM = process.env.EMAIL_FROM || "onboarding@resend.dev";
async function sendEmail(to, subject, body) {
  if (!RESEND_KEY) {
    console.log(`\n=== EMAIL (no RESEND_KEY, logging only) to ${to} ===\n${subject}\n${body}\n===================\n`);
    return;
  }
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: EMAIL_FROM, to, subject, text: body }),
    });
    if (!r.ok) {
      const t = await r.text();
      console.error(`Resend error ${r.status}: ${t}`);
    } else {
      console.log(`email sent to ${to}`);
    }
  } catch (e) {
    console.error("email send failed:", e.message);
  }
}

/* ---------------- request helpers ---------------- */
function readBody(req, raw = false) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const buf = Buffer.concat(chunks);
      if (raw) return resolve(buf);
      try { resolve(buf.length ? JSON.parse(buf.toString()) : {}); }
      catch { reject(new Error("bad json")); }
    });
    req.on("error", reject);
  });
}
function json(res, code, obj, headers = {}) {
  res.writeHead(code, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
}
function getCookie(req, name) {
  const m = (req.headers.cookie || "").match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}
function sessionEmail(req) {
  const s = verify(getCookie(req, "tsa_session"));
  return s && s.t === "session" ? s.email : null;
}

/* ---------------- routes ---------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE_URL);
  const route = `${req.method} ${url.pathname}`;
  // CORS for the static frontend (same-origin deploys can delete this block)
  res.setHeader("Access-Control-Allow-Origin", BASE_URL);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  try {
    /* ---- auth: request a magic link ---- */
    if (route === "POST /api/auth/request") {
      const { email } = await readBody(req);
      if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(res, 400, { error: "valid email required" });
      const token = sign({ t: "magic", email: email.toLowerCase(), exp: Date.now() + 15 * 60 * 1000 });
      const link = `${BASE_URL}/api/auth/verify?token=${encodeURIComponent(token)}`;
      await sendEmail(email, "Your Tech Sales Accelerator sign-in link",
        `Click to sign in (valid 15 minutes):\n\n${link}\n\nIf you didn't request this, ignore it.`);
      return json(res, 200, { ok: true });
    }

    /* ---- auth: verify link, set session, bounce to app ---- */
    if (route === "GET /api/auth/verify") {
      const obj = verify(url.searchParams.get("token"));
      if (!obj || obj.t !== "magic") return json(res, 400, { error: "invalid or expired link" });
      const session = sign({ t: "session", email: obj.email, exp: Date.now() + 30 * 24 * 3600 * 1000 });
      res.writeHead(302, {
        "Set-Cookie": `tsa_session=${encodeURIComponent(session)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 3600}`,
        Location: BASE_URL + "/",
      });
      return res.end();
    }

    /* ---- who am I + what do I own ---- */
    if (route === "GET /api/me") {
      const email = sessionEmail(req);
      if (!email) return json(res, 401, { error: "not signed in" });
      return json(res, 200, { email, entitlements: getEntitlements(email) });
    }

    /* ---- create a Stripe Checkout session ---- */
    if (route === "POST /api/checkout") {
      const email = sessionEmail(req);
      if (!email) return json(res, 401, { error: "sign in first" });
      const { product } = await readBody(req);
      if (!PRICES[product]) return json(res, 400, { error: "unknown product" });
      if (getEntitlements(email).includes(product)) return json(res, 400, { error: "already owned" });
      const isSub = SUBSCRIPTION_PRODUCTS.has(product);
      const session = await stripe.checkout.sessions.create({
        mode: isSub ? "subscription" : "payment",
        customer_email: email,
        line_items: [{ price: PRICES[product], quantity: 1 }],
        allow_promotion_codes: true,
        metadata: { product, email },
        ...(isSub ? { subscription_data: { metadata: { product, email } } } : {}),
        success_url: `${BASE_URL}/?purchase=success&track=${product}`,
        cancel_url: `${BASE_URL}/?purchase=cancelled`,
      });
      return json(res, 200, { url: session.url });
    }

    /* ---- Stripe webhook: fulfill on payment ---- */
    if (route === "POST /api/webhook") {
      const raw = await readBody(req, true);
      let event;
      try {
        event = stripe.webhooks.constructEvent(raw, req.headers["stripe-signature"], WEBHOOK_SECRET);
      } catch (e) {
        return json(res, 400, { error: `webhook signature: ${e.message}` });
      }
      if (event.type === "checkout.session.completed") {
        const s = event.data.object;
        const email = s.metadata?.email || s.customer_email;
        const product = s.metadata?.product;
        if (email && product) grantEntitlement(email, product);
        if (email && s.subscription) rememberSub(s.subscription, email);
      }
      if (event.type === "customer.subscription.deleted") {
        const sub = event.data.object;
        const email = sub.metadata?.email || emailForSub(sub.id);
        const product = sub.metadata?.product || "membership";
        if (email) revokeEntitlement(email, product);
      }
      return json(res, 200, { received: true });
    }

    /* ---- health ---- */
    if (route === "GET /api/health") return json(res, 200, { ok: true });

    json(res, 404, { error: "not found" });
  } catch (e) {
    console.error(e);
    json(res, 500, { error: "server error" });
  }
});

server.listen(PORT, () => console.log(`TSA backend on :${PORT} (${BASE_URL})`));
