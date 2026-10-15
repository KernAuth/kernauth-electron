import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { readFileSync, readSync } from "node:fs";

const API = "https://api.kernauth.com";
const APP_ID = "__PUBLIC_APP_ID__";
const PUBLIC_KEY = "__PUBLIC_KEY__";

export class KernAuth {
  success = false;
  message = "";
  entitlement = null;

  constructor(api = API, appId = APP_ID, publicKey = PUBLIC_KEY) {
    this.api = api;
    this.appId = appId;
    this.publicKey = publicKey;
  }

  validate(licenseKey, installationId) {
    return this.call("validate", licenseKey, installationId, "License is active");
  }

  async call(mode, licenseKey, installationId, okMessage) {
    try {
      const ent = await request(mode, licenseKey, installationId, this.api, this.appId, this.publicKey);
      this.entitlement = {
        status: ent.status,
        features: JSON.stringify(sorted(typeof ent.features === "string" ? JSON.parse(ent.features) : ent.features)),
        license_id: ent.license_id,
        expires_at: ent.expires_at,
      };
    } catch (error) {
      this.success = false;
      this.message = error instanceof Error ? error.message : "request failed";
      this.entitlement = null;
      return false;
    }
    this.success = true;
    this.message = okMessage;
    return true;
  }
}

function readLine() {
  const buffer = Buffer.alloc(4096);
  let text = "";
  while (!text.includes("\n")) {
    const count = readSync(0, buffer, 0, buffer.length, null);
    if (count === 0) break;
    text += buffer.subarray(0, count).toString("utf8");
  }
  return text.split("\n")[0]?.trim() ?? "";
}

function licenseKey() {
  const fromEnv = globalThis.process.env.KERN_LICENSE_KEY?.trim();
  if (fromEnv) return fromEnv;
  if (globalThis.process.stdin.isTTY) globalThis.process.stdout.write("Enter license: ");
  return readLine();
}

function acceptableHwid(value) {
  return /^[A-Za-z0-9_-]{8,64}$/.test(value);
}

function machineHwid() {
  if (globalThis.process.platform === "win32") {
    return execFileSync("powershell.exe", ["-NoProfile", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"], { encoding: "utf8" });
  }
  if (globalThis.process.platform === "darwin") {
    const output = execFileSync("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], { encoding: "utf8" });
    return output.match(/"IOPlatformUUID" = "([^"]+)"/)?.[1] ?? "";
  }
  return readFileSync("/etc/machine-id", "utf8");
}

function installationId() {
  const fromEnv = globalThis.process.env.KERN_INSTALLATION_ID?.trim();
  if (fromEnv) return fromEnv;
  const hwid = machineHwid().trim();
  if (acceptableHwid(hwid)) return hwid;
  throw new Error("Could not read the HWID");
}

if (globalThis.process.argv[1]?.endsWith("electron.mjs")) {
  const key = licenseKey();
  const hwid = installationId();
  const app = new KernAuth(API, APP_ID, PUBLIC_KEY);
  if (!await app.validate(key, hwid)) {
    throw new Error(app.message);
  }
  globalThis.console.log(`Status: ${app.entitlement.status}`);
  globalThis.console.log(`Features: ${app.entitlement.features}`);
  globalThis.console.log(`License: ${app.entitlement.license_id}`);
  globalThis.console.log(`Check expires: ${app.entitlement.expires_at}`);
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 60_000));
    try {
      await heartbeat(key, hwid, API, APP_ID);
    } catch (error) {
      globalThis.console.log(error instanceof Error ? error.message : "heartbeat failed");
      globalThis.process.exit(1);
    }
  }
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

export function verifyGrant(grant, nonce, app = APP_ID, publicKey = PUBLIC_KEY, now = Date.now()) {
  const ent = grant.entitlement;
  if (ent.protocol_version !== 1 || ent.nonce !== nonce || ent.application_id !== app ||
      ent.status !== "active" || Date.parse(ent.expires_at) <= now) return false;
  const raw = decodeBase64(publicKey);
  const signature = decodeBase64(grant.signature);
  if (raw === null || raw.length !== 32 || signature === null || signature.length !== 64) return false;
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  return verifySignature(null, canonical(ent), key, signature);
}

async function failureMessage(response, fallback) {
  const failure = await response.json().catch(() => null);
  const message = failure?.error?.message;
  return typeof message === "string" && message !== "" ? message : fallback;
}

async function heartbeat(licenseKey, installationId, api, appId) {
  const nonce = randomBytes(24).toString("base64url");
  const fingerprint = createHash("sha256").update(`kernauth-device-v1:${installationId}`).digest("hex");
  const response = await globalThis.fetch(`${api}/v1/client/heartbeat`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: appId, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(await failureMessage(response, `heartbeat failed (${response.status})`));
  const payload = await response.json().catch(() => null);
  if (payload?.ok !== true) throw new Error("heartbeat failed");
}

async function request(mode, licenseKey, installationId, api = API, appId = APP_ID, publicKey = PUBLIC_KEY) {
  const nonce = randomBytes(24).toString("base64url");
  const fingerprint = createHash("sha256").update(`kernauth-device-v1:${installationId}`).digest("hex");
  const response = await globalThis.fetch(`${api}/v1/client/${mode}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ protocol_version: 1, public_app_id: appId, client_version: "1.0.0",
      license_key: licenseKey, fingerprint_version: 1, device_fingerprint: fingerprint,
      installation_id: installationId, nonce }),
  });
  if (!response.ok) throw new Error(await failureMessage(response, `${mode} failed (${response.status})`));
  const grant = await response.json();
  if (!verifyGrant(grant, nonce, appId, publicKey)) throw new Error("Invalid or expired signed entitlement");
  return grant.entitlement;
}
