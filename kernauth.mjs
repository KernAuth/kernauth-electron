import { createHash, createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";

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

export function verifyGrant(grant, nonce, app, publicKey, now = Date.now()) {
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

function acceptableHwid(value) {
  return /^[A-Za-z0-9_-]{8,64}$/.test(value);
}

function installationId() {
  const fromEnv = globalThis.process.env.KERN_INSTALLATION_ID?.trim();
  if (fromEnv && acceptableHwid(fromEnv)) return fromEnv;
  if (globalThis.process.platform !== "win32") throw new Error("Could not read the HWID");
  const hwid = execFileSync("powershell.exe", ["-NoProfile", "-Command",
    "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"], { encoding: "utf8" }).trim();
  if (!acceptableHwid(hwid)) throw new Error("Could not read the HWID");
  return hwid;
}

async function failureMessage(response, fallback) {
  const failure = await response.json().catch(() => null);
  const message = failure?.error?.message;
  return typeof message === "string" && message !== "" ? message : fallback;
}

export class KernAuth {
  constructor(api, appId, publicKey) {
    this.api = api;
    this.appId = appId;
    this.publicKey = publicKey;
    this.message = "";
    this.entitlement = null;
    this.installation = null;
    this.sessionSalt = null;
    this.timeBucket = null;
  }

  device() {
    if (!this.installation) this.installation = installationId();
    const fingerprint = createHash("sha256").update(`kernauth-device-v1:${this.installation}`).digest("hex");
    return { installation: this.installation, fingerprint };
  }

  async initialize() {
    try {
      const { installation, fingerprint } = this.device();
      this.sessionSalt = randomBytes(32).toString("hex");
      this.timeBucket = null;
      const nonce = randomBytes(24).toString("base64url");
      const response = await fetch(`${this.api}/v1/client/initialize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          protocol_version: 1,
          public_app_id: this.appId,
          client_version: "1.0.0",
          fingerprint_version: 1,
          device_fingerprint: fingerprint,
          installation_id: installation,
          session_salt: this.sessionSalt,
          nonce,
        }),
      });
      if (!response.ok) throw new Error(await failureMessage(response, `initialize failed (${response.status})`));
      const payload = await response.json();
      if (payload?.ok !== true || typeof payload.time_bucket !== "string" || payload.time_bucket === "") {
        throw new Error("Initialize response was incomplete");
      }
      this.timeBucket = payload.time_bucket;
      this.message = "Session ready";
      return true;
    } catch (error) {
      this.sessionSalt = null;
      this.timeBucket = null;
      this.message = error instanceof Error ? error.message : "initialize failed";
      return false;
    }
  }

  async post(mode, licenseKey) {
    const { installation, fingerprint } = this.device();
    const nonce = randomBytes(24).toString("base64url");
    const body = {
      protocol_version: 1,
      public_app_id: this.appId,
      client_version: "1.0.0",
      license_key: licenseKey,
      fingerprint_version: 1,
      device_fingerprint: fingerprint,
      installation_id: installation,
      nonce,
    };
    if (mode === "validate") {
      if (!this.sessionSalt || !this.timeBucket) throw new Error("Call initialize first");
      body.save_hwid = true;
      body.session_salt = this.sessionSalt;
      body.time_bucket = this.timeBucket;
    }
    const response = await fetch(`${this.api}/v1/client/${mode}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(await failureMessage(response, `${mode} failed (${response.status})`));
    const payload = await response.json();
    if (mode === "heartbeat") {
      if (payload?.ok !== true) throw new Error("heartbeat failed");
      return null;
    }
    if (!verifyGrant(payload, nonce, this.appId, this.publicKey)) {
      throw new Error("Invalid or expired signed entitlement");
    }
    return payload.entitlement;
  }

  async validate(licenseKey) {
    try {
      this.entitlement = await this.post("validate", licenseKey);
      this.message = "License is active";
      return true;
    } catch (error) {
      this.entitlement = null;
      this.message = error instanceof Error ? error.message : "validate failed";
      return false;
    }
  }

  heartbeat(licenseKey) {
    return this.post("heartbeat", licenseKey);
  }
}
