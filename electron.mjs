import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { Buffer } from "node:buffer";

const API = "https://api.kernauth.com";
const APP_ID = "__PUBLIC_APP_ID__";
const KEY_ID = "__KEY_ID__";
const PUBLIC_KEY = "__PUBLIC_KEY__";

export class KernAuth {
  success = false;
  message = "";

  constructor(api = API, appId = APP_ID, keyId = KEY_ID, publicKey = PUBLIC_KEY) {
    this.api = api;
    this.appId = appId;
    this.keyId = keyId;
    this.publicKey = publicKey;
  }

  activate(licenseKey, installationId) {
    return this.call("activate", licenseKey, installationId, "License is active");
  }

  validate(licenseKey, installationId) {
    return this.call("validate", licenseKey, installationId, "License is active");
  }

  deactivate(licenseKey, installationId) {
    return this.call("deactivate", licenseKey, installationId, "Device deactivated");
  }

  async call(mode, licenseKey, installationId, okMessage) {
    try {
      await request(mode, licenseKey, installationId, this.api, this.appId, this.keyId, this.publicKey);
    } catch (error) {
      this.success = false;
      this.message = error instanceof Error ? error.message : "request failed";
      return false;
    }
    this.success = true;
    this.message = okMessage;
    return true;
  }
}

if (globalThis.process.argv[1]?.endsWith("electron.mjs")) {
  const license = globalThis.process.env.KERN_LICENSE_KEY;
  const installation = globalThis.process.env.KERN_INSTALLATION_ID;
  if (!license || !installation) throw new Error("Set KERN_LICENSE_KEY and KERN_INSTALLATION_ID");
  const app = new KernAuth(API, APP_ID, KEY_ID, PUBLIC_KEY);
  if (!await app.activate(license, installation) ||
      !await app.validate(license, installation) ||
      !await app.deactivate(license, installation)) {
    throw new Error(app.message);
  }
  globalThis.console.log(app.message);
}

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

async function request(mode, licenseKey, installationId, api = API, appId = APP_ID, keyId = KEY_ID, publicKey = PUBLIC_KEY) {
  const nonce = randomBytes(24).toString("base64url");
  const fingerprint = createHash("sha256").update(`kernauth-device-v1:${installationId}`).digest("hex");
  const response = await globalThis.fetch(`${api}/v1/client/${mode}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: appId, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(`${mode} failed (${response.status})`);
  const grant = await response.json();
  if (mode === "deactivate") {
    if (grant.deactivated !== true) throw new Error("Deactivation was not confirmed");
  } else if (!verifyGrant(grant, nonce, appId, keyId, publicKey)) throw new Error("Invalid or expired signed entitlement");
}
