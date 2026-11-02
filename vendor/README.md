# Vendored libraries

Served from this directory so the app needs no third-party script hosts at runtime
(the Content-Security-Policy only allows `script-src 'self'`). Files are byte-for-byte
copies of the published npm packages.

| File | Package | License | SHA-256 |
|------|---------|---------|---------|
| `qrcode-generator-2.0.4.js` | [`qrcode-generator@2.0.4`](https://www.npmjs.com/package/qrcode-generator) (`dist/qrcode.js`) | MIT (header in file) | `79ec86f82856005b1c887905cfccfcfbec3821ca61c7fd5a952faa5f778f791c` |
| `jsQR-1.4.0.js` | [`jsqr@1.4.0`](https://www.npmjs.com/package/jsqr) (`dist/jsQR.js`) | Apache-2.0 (`jsQR-LICENSE.txt`) | `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859` |

`jsQR` is only loaded when someone opens the camera scanner and the browser has no
native `BarcodeDetector`.

To verify: `sha256sum vendor/*.js`
