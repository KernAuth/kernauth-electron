import { createDecipheriv } from "node:crypto";
import { readSync } from "node:fs";
import { KernAuth } from "./kernauth.mjs";

const app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__");

function unwrapPayload(wrapKey, payloadBox) {
  if (typeof wrapKey !== "string" || typeof payloadBox !== "string") return null;
  try {
    const key = Buffer.from(wrapKey, "base64");
    const box = Buffer.from(payloadBox, "base64");
    if (key.length !== 32 || box.length <= 28) return null;
    const nonce = box.subarray(0, 12);
    const tag = box.subarray(box.length - 16);
    const data = box.subarray(12, box.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  } catch {
    return null;
  }
}

function licenseKey() {
  const fromEnv = globalThis.process.env.KERN_LICENSE_KEY?.trim();
  if (fromEnv) return fromEnv;
  if (globalThis.process.stdin.isTTY) globalThis.process.stdout.write("Enter license: ");
  const buffer = Buffer.alloc(256);
  let text = "";
  for (;;) {
    const count = readSync(0, buffer, 0, buffer.length, null);
    if (count === 0) break;
    text += buffer.subarray(0, count).toString("utf8");
    if (text.includes("\n")) break;
  }
  return text.split("\n")[0]?.trim() ?? "";
}

const key = licenseKey();
if (!await app.validate(key)) {
  globalThis.console.log(app.message);
  globalThis.process.exit(1);
}
const featureRecord = typeof app.entitlement.features === "string"
  ? JSON.parse(app.entitlement.features)
  : app.entitlement.features;
const payloadKey = unwrapPayload(featureRecord?.wrap_key, featureRecord?.payload_box);
if (payloadKey === null) {
  globalThis.console.log("The payload key could not open this build.");
  globalThis.process.exit(1);
}
payloadKey.fill(0);
// Decrypt the program with the opened key. Drop it when the heartbeat fails.
globalThis.console.log("Payload opened");
globalThis.console.log(`Status: ${app.entitlement.status}`);
globalThis.console.log(`License: ${app.entitlement.license_id}`);
globalThis.console.log(`Check expires: ${app.entitlement.expires_at}`);
for (;;) {
  await new Promise((resolve) => setTimeout(resolve, 60_000));
  try {
    await app.heartbeat(key);
  } catch (error) {
    globalThis.console.log(error instanceof Error ? error.message : "heartbeat failed");
    globalThis.process.exit(1);
  }
}
