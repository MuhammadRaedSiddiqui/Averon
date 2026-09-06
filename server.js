"use strict";

/**
 * Agent Forge shared client backend.
 *
 * One service hosts every client, so routes are org-scoped:
 *
 *   Vapi tool -> POST /webhook/:org/:capability -> Make webhook -> Supabase
 *
 * This handler is generic and permanent. Onboarding a client is configuration
 * only — two environment variables per capability — so no per-client code is
 * generated, committed or deployed. The previous design generated an Express
 * route per client into a diff that nothing ever applied, which is why no
 * deployed assistant's tools had ever worked.
 */

const crypto = require("crypto");
const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

// Capabilities that have a Make scenario behind them. human_transfer is
// handled inside Vapi and never reaches this service.
const CAPABILITIES = new Set([
  "availability",
  "booking",
  "cancellation",
  "rescheduling",
]);

const FORWARD_TIMEOUT_MS = Number(process.env.MAKE_FORWARD_TIMEOUT_MS || 20000);

/** Environment-variable suffix for an organization id. */
function envSlug(organizationId) {
  return String(organizationId).toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

/** Whether this client has been enabled on this service. */
function clientEnabled(organizationId) {
  return process.env[`CLIENT_${envSlug(organizationId)}_ENABLED`] === "true";
}

/** The Make webhook this (client, capability) forwards to, if configured. */
function makeTargetUrl(organizationId, capability) {
  return process.env[
    `MAKE_${envSlug(organizationId)}_${capability.toUpperCase()}_URL`
  ];
}

function verifyHmac(req, res, next) {
  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.get("x-signature");

  if (!secret || !signature) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const payload = JSON.stringify(req.body || {});
  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

  const given = Buffer.from(signature);
  const want = Buffer.from(expected);

  // timingSafeEqual throws when lengths differ, so a malformed signature
  // would have surfaced as a 500 rather than a 401. Compare lengths first;
  // the length of a rejected signature is not a useful secret.
  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return next();
}

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.post("/webhook/:org/:capability", verifyHmac, async (req, res) => {
  const { org, capability } = req.params;

  if (!CAPABILITIES.has(capability)) {
    return res.status(404).json({ error: "Unknown capability", capability });
  }

  if (!clientEnabled(org)) {
    return res.status(404).json({ error: "Unknown client", organization: org });
  }

  const target = makeTargetUrl(org, capability);
  if (!target) {
    // Enabled but not wired: a configuration gap, not a bad request. 503 so
    // the caller can retry once onboarding finishes setting the variable.
    return res.status(503).json({
      error: "Client capability is not configured",
      organization: org,
      capability,
    });
  }

  try {
    const forwarded = await axios.post(target, req.body, {
      headers: { "Content-Type": "application/json" },
      timeout: FORWARD_TIMEOUT_MS,
    });
    return res.status(200).json(forwarded.data);
  } catch (error) {
    const status = error.response ? error.response.status : null;
    console.error(
      `[${org}] ${capability} forward failed:`,
      status || error.code || error.message
    );
    // 502: this service worked, the thing it depends on did not.
    return res.status(502).json({
      error: "Upstream automation failed",
      organization: org,
      capability,
    });
  }
});

const port = Number(process.env.PORT || 3000);

/* istanbul ignore next -- not exercised when imported by tests */
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Agent Forge backend listening on ${port}`);
  });
}

module.exports = {
  app,
  verifyHmac,
  envSlug,
  clientEnabled,
  makeTargetUrl,
  CAPABILITIES,
};
