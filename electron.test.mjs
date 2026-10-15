import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { URL } from "node:url";
import { canonical, verifyGrant } from "./kernauth.mjs";

const fixture = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
for (const vector of fixture.vectors) {
  test(`Electron verifies ${vector.name}`, () => {
    const grant = { entitlement: vector.fields, signature: vector.signature };
    const now = Date.parse("2026-01-01T00:01:00Z");
    assert.equal(canonical(vector.fields).toString("utf8"), vector.canonical);
    assert.equal(verifyGrant(grant, vector.fields.nonce, vector.fields.application_id, vector.public_key, now), true);
    assert.equal(verifyGrant(grant, "wrong", vector.fields.application_id, vector.public_key, now), false);
    assert.equal(verifyGrant(grant, vector.fields.nonce, "pub_other_app", vector.public_key, now), false);
    assert.equal(verifyGrant({ ...grant, signature: `${vector.signature}AA` }, vector.fields.nonce,
      vector.fields.application_id, vector.public_key, now), false);
    assert.equal(verifyGrant(grant, vector.fields.nonce, vector.fields.application_id,
      vector.public_key, Date.parse(vector.fields.expires_at)), false);
    assert.equal(verifyGrant({ ...grant, entitlement: { ...vector.fields, device_id: "other" } },
      vector.fields.nonce, vector.fields.application_id, vector.public_key, now), false);
    assert.equal(verifyGrant({ ...grant, entitlement: { ...vector.fields, status: "revoked" } },
      vector.fields.nonce, vector.fields.application_id, vector.public_key, now), false);
  });
}
