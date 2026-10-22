import { readSync } from "node:fs";
import { KernAuth } from "./kernauth.mjs";

const app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__");

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

if (!await app.initialize()) {
  globalThis.console.log(app.message);
  globalThis.process.exit(1);
}
const key = licenseKey();
if (!await app.validate(key)) {
  globalThis.console.log(app.message);
  globalThis.process.exit(1);
}
if (app.entitlement) app.entitlement.features = "";
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
