# KernAuth Electron example

Paste the public app ID and public key from Developers into `main.mjs`. Electron main process on Node 20 or newer. Keep the license key out of the renderer.

## Start

```js
const app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__");
await app.initialize();
await app.validate(key);
```

Call initialize before validate so the session salt and server time bucket are set. The last argument is the version. Leave it out when Require this version is off: `new KernAuth(api, appId, publicKey, "1.0.0")`. Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The library reads the Windows user SID and checks the signature. The program then asks the server again every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

## Run

```
node --test electron.test.mjs
node main.mjs
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
