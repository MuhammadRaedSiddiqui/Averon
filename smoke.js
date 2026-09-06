/**
 * Functional smoke test for the generic webhook route.
 *
 * Starts the real app and a stand-in "Make" listener, then exercises the cases
 * an operator has to be able to tell apart: unsigned, wrong signature, unknown
 * client, unknown capability, enabled-but-unwired, upstream failure, success.
 *
 * No mocking of the handler itself — this is the app as deployed.
 */

const crypto = require("crypto");
const express = require("express");

process.env.WEBHOOK_SECRET = "test-secret";
process.env.CLIENT_NORTHGATE_DENTAL_ENABLED = "true";
process.env.CLIENT_UNWIRED_CO_ENABLED = "true";

let received = null;

function sign(body) {
  return crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(JSON.stringify(body))
    .digest("hex");
}

async function main() {
  // Stand-in for Make.
  const upstream = express();
  upstream.use(express.json());
  upstream.post("/hook-ok", (req, res) => {
    received = req.body;
    res.json({ ok: true, echoed: req.body });
  });
  upstream.post("/hook-bad", (_req, res) => res.status(500).json({ error: "make blew up" }));
  const upstreamServer = await new Promise((resolve) => {
    const s = upstream.listen(0, () => resolve(s));
  });
  const upstreamPort = upstreamServer.address().port;

  process.env.MAKE_NORTHGATE_DENTAL_BOOKING_URL = `http://127.0.0.1:${upstreamPort}/hook-ok`;
  process.env.MAKE_NORTHGATE_DENTAL_CANCELLATION_URL = `http://127.0.0.1:${upstreamPort}/hook-bad`;

  const { app } = require("./server.js");
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  const body = { caller: "+15551234567", date: "2026-09-10" };
  const results = [];

  async function call(label, path, opts = {}) {
    const useBody = opts.body === undefined ? body : opts.body;
    const headers = { "Content-Type": "application/json" };
    if (opts.signature !== null) {
      headers["x-signature"] = opts.signature || sign(useBody);
    }
    const res = await fetch(`${base}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(useBody),
    });
    let json = null;
    try {
      json = await res.json();
    } catch {
      /* empty body */
    }
    results.push({ label, status: res.status, body: json });
  }

  await call("health (GET)", "");
  results.pop();
  const health = await fetch(`${base}/health`);
  results.push({ label: "GET /health", status: health.status, body: await health.json() });

  await call("no signature", "/webhook/northgate_dental/booking", { signature: null });
  await call("wrong signature", "/webhook/northgate_dental/booking", { signature: "deadbeef" });
  await call("unknown capability", "/webhook/northgate_dental/teleport");
  await call("unknown client", "/webhook/nobody_co/booking");
  await call("enabled but unwired", "/webhook/unwired_co/booking");
  await call("upstream fails", "/webhook/northgate_dental/cancellation");
  await call("success", "/webhook/northgate_dental/booking");

  for (const r of results) {
    console.log(`  ${String(r.status).padEnd(4)} ${r.label.padEnd(22)} ${JSON.stringify(r.body)}`);
  }

  const expected = {
    "GET /health": 200,
    "no signature": 401,
    "wrong signature": 401,
    "unknown capability": 404,
    "unknown client": 404,
    "enabled but unwired": 503,
    "upstream fails": 502,
    success: 200,
  };

  let failures = 0;
  for (const r of results) {
    if (expected[r.label] !== r.status) {
      console.log(`  MISMATCH ${r.label}: got ${r.status}, expected ${expected[r.label]}`);
      failures += 1;
    }
  }
  if (JSON.stringify(received) !== JSON.stringify(body)) {
    console.log(`  MISMATCH forwarded body: ${JSON.stringify(received)}`);
    failures += 1;
  } else {
    console.log("  forwarded body reached upstream unchanged");
  }

  server.close();
  upstreamServer.close();
  console.log(`\n${failures} failure(s)`);
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
