/**
 * WhatsApp Cloud API webhook -> forwards sanitized events to Hermes.
 * Deployed as a Cloudflare Worker at: https://hasankhshifat.com/webhook/whatsapp
 *
 * Required secrets (set with `wrangler secret put <NAME>`, never hard-code them):
 *   WHATSAPP_VERIFY_TOKEN   - any string you invent; enter the SAME value in
 *                             Meta App Dashboard > WhatsApp > Configuration > Webhook.
 *   WHATSAPP_APP_SECRET     - Meta App Dashboard > App Settings > Basic > App Secret.
 *   HERMES_WEBHOOK_URL      - the URL Hermes listens on for incoming WhatsApp events.
 *   HERMES_API_KEY          - whatever auth token/key Hermes expects (sent as Bearer token below;
 *                             change the header in forwardToHermes() if Hermes expects something else).
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== "/webhook/whatsapp") {
      return new Response("Not found", { status: 404 });
    }

    if (request.method === "GET") return handleVerification(url, env);
    if (request.method === "POST") return handleEvent(request, env, ctx);

    return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  },
};

/* ---- Meta webhook verification (one-time handshake when you save the webhook URL) ---- */
function handleVerification(url, env) {
  const mode = url.searchParams.get("hub.mode");
  const token = url.searchParams.get("hub.verify_token");
  const challenge = url.searchParams.get("hub.challenge");

  if (mode === "subscribe" && token && env.WHATSAPP_VERIFY_TOKEN && timingSafeEqual(token, env.WHATSAPP_VERIFY_TOKEN)) {
    return new Response(challenge ?? "", { status: 200, headers: { "Content-Type": "text/plain" } });
  }
  return new Response("Verification failed", { status: 403 });
}

/* ---- Incoming WhatsApp events ---- */
async function handleEvent(request, env, ctx) {
  const rawBody = await request.text();
  const signatureHeader = request.headers.get("X-Hub-Signature-256") || "";

  const valid = await verifySignature(rawBody, signatureHeader, env.WHATSAPP_APP_SECRET);
  if (!valid) {
    // Don't tell the caller which part failed; just refuse.
    return new Response("Invalid signature", { status: 401 });
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    // Acknowledge anyway - Meta will retry malformed bodies forever otherwise, and
    // a parse failure on our end isn't something retrying will fix.
    return new Response("OK", { status: 200 });
  }

  // Respond to Meta immediately; do the forwarding after the response is sent so
  // Meta always gets a fast 200 regardless of how long Hermes takes to answer.
  ctx.waitUntil(forwardToHermes(payload, env));

  return new Response("OK", { status: 200 });
}

/* ---- HMAC-SHA256 signature check (X-Hub-Signature-256: sha256=<hex>) ---- */
async function verifySignature(rawBody, signatureHeader, appSecret) {
  if (!appSecret || !signatureHeader.startsWith("sha256=")) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(appSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
  const expectedHex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("");

  return timingSafeEqual(signatureHeader.slice(7), expectedHex);
}

/* Constant-time string compare, to avoid leaking info through response-time differences. */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---- Strip the payload down to what Hermes actually needs, then forward it ---- */
function sanitize(payload) {
  const messages = [];
  for (const entry of payload.entry ?? []) {
    for (const change of entry.changes ?? []) {
      const v = change.value ?? {};
      for (const msg of v.messages ?? []) {
        messages.push({
          from: msg.from,
          id: msg.id,
          timestamp: msg.timestamp,
          type: msg.type,
          text: msg.text?.body,
          // Add other fields here (image, button, interactive, etc.) as Hermes needs them.
        });
      }
    }
  }
  return { messages };
}

async function forwardToHermes(payload, env) {
  if (!env.HERMES_WEBHOOK_URL) {
    console.error("HERMES_WEBHOOK_URL is not set; dropping event.");
    return;
  }
  const body = JSON.stringify(sanitize(payload));

  // Forwarding gets a few quick retries since Meta won't retry on our behalf once we've said 200.
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(env.HERMES_WEBHOOK_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(env.HERMES_API_KEY ? { Authorization: `Bearer ${env.HERMES_API_KEY}` } : {}),
        },
        body,
      });
      if (res.ok) return;
      console.error(`Hermes responded ${res.status} on attempt ${attempt}`);
    } catch (err) {
      console.error(`Hermes forward failed on attempt ${attempt}:`, err);
    }
    await new Promise(r => setTimeout(r, attempt * 500));
  }
  console.error("Giving up forwarding event to Hermes after 3 attempts.");
}
