"use strict";

const crypto = require("crypto");
const express = require("express");

const app = express();
app.use(express.json());

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

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return next();
}

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Agent Forge backend listening on ${port}`);
});

module.exports = { app, verifyHmac };
