# KernAuth Electron example

Protocol example for the Electron main process on Node 20+. This is not the official SDK. The official client is the C++ SDK. Keep the license key out of the renderer. Call these methods from the main process and send only the result to the window.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `electron.mjs`.

```
node --test electron.test.mjs
```

Run with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

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
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
