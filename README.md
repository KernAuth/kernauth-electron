# KernAuth Electron example

Paste the public app ID, key ID, and public key from Developers into `electron.mjs`. Electron main process on Node 20 or newer. Keep the license key out of the renderer. Call validate from the main process and send only the result to the window.

## Instance

```js
const app = new KernAuth(
  "https://api.kernauth.com",
  "__PUBLIC_APP_ID__",
  "__KEY_ID__",
  "__PUBLIC_KEY__",
);
```

## Validate

```js
if (!await app.validate(license, installation)) {
  throw new Error(app.message);
}
console.log(`Status: ${app.entitlement.status}`);
console.log(`Features: ${app.entitlement.features}`);
console.log(`License: ${app.entitlement.license_id}`);
console.log(`Check expires: ${app.entitlement.expires_at}`);
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
node --test electron.test.mjs
node electron.mjs
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
