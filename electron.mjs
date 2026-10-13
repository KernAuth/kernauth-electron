// Electron main-process protocol example. Keep license checks out of the renderer.
// node electron.mjs (Node 20+); adapt request() to an Electron IPC handler.
import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { Buffer } from "node:buffer";

const API = "https://api.kernauth.com";
const APP_ID = "__PUBLIC_APP_ID__";
const KEY_ID = "__KEY_ID__";
const PUBLIC_KEY = "__PUBLIC_KEY__";
const FIELDS = ["protocol_version", "entitlement_id", "application_id", "license_id", "status",
  "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"];

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
  }
  return value;
}

function decodeBase64(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  return Buffer.from(value, "base64");
}

export function canonical(ent) {
  const lines = FIELDS.map((name) => {
    const value = name === "features"
      ? JSON.stringify(sorted(typeof ent.features === "string" ? JSON.parse(ent.features) : ent.features))
      : String(ent[name]);
    if (value.includes("\n") || value.includes("\r")) throw new Error("Invalid entitlement field");
    return `${name}=${value}`;
  });
  return Buffer.from(`${lines.join("\n")}\n`, "utf8");
}

export function verifyGrant(grant, nonce, app = APP_ID, keyId = KEY_ID, publicKey = PUBLIC_KEY, now = Date.now()) {
  const ent = grant.entitlement;
  if (ent.protocol_version !== 1 || ent.nonce !== nonce || ent.application_id !== app ||
      ent.key_id !== keyId || ent.status !== "active" || Date.parse(ent.expires_at) <= now) return false;
  const raw = decodeBase64(publicKey);
  const signature = decodeBase64(grant.signature);
  if (raw === null || raw.length !== 32 || signature === null || signature.length !== 64) return false;
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  return verifySignature(null, canonical(ent), key, signature);
}

async function request(mode, licenseKey, installationId) {
  const nonce = randomBytes(24).toString("base64url");
  const fingerprint = createHash("sha256").update(`kernauth-device-v1:${installationId}`).digest("hex");
  const response = await globalThis.fetch(`${API}/v1/client/${mode}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: APP_ID, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(`${mode} failed (${response.status})`);
  const grant = await response.json();
  if (mode === "deactivate") {
    if (grant.deactivated !== true) throw new Error("Deactivation was not confirmed");
  } else if (!verifyGrant(grant, nonce)) throw new Error("Invalid or expired signed entitlement");
}

if (globalThis.process.argv[1]?.endsWith("electron.mjs")) {
  const license = globalThis.process.env.KERN_LICENSE_KEY;
  const installation = globalThis.process.env.KERN_INSTALLATION_ID; // Persist once per device.
  if (!license || !installation) throw new Error("Set KERN_LICENSE_KEY and KERN_INSTALLATION_ID");
  for (const mode of ["activate", "validate", "deactivate"]) await request(mode, license, installation);
  globalThis.console.log("Signed entitlement verified and device deactivated");
}
