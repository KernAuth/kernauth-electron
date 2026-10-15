# KernAuth Electron example

Paste the public app ID and public key from Developers into `main.mjs`. Electron main process on Node 20 or newer. Keep the license key out of the renderer.

## Start

```js
const app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__");
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The library reads the Windows user SID and checks the signature. The program then asks the server again every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

## Run

```
node --test electron.test.mjs
node main.mjs
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
