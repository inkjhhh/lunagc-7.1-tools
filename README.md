# LunaGC 7.1 playable toolchain

Makes the 7.1 client talk to a local LunaGC server. Three pieces that each
fix one breakage in the stock setup:

| Piece | Fixes |
|---|---|
| `patch/` (dbghelp proxy DLL) | MDK `(2,0,4)` + SDK crypto hooks |
| `tlsfront/` | routes the SDK curl stack to the local server |
| `scripts/` | one-click server start, account creation, DLL swap |

Server-side changes (rsa_key serving, OAEP paddings, build fixes) live in the
`playable-7.1` branch of the LunaGC fork.

## Background

Two independent blockers stop a stock 7.1 client from reaching a private
server, plus one deployment gotcha:

1. **MDK `(2,0,4)`**: mhypbase enumerates loaded modules and calls
   `WinVerifyTrust` on each (found via hooked caller
   `MHYPBase.dll+0x198B915`). Any replaced `Astrolabe.dll` (or any unsigned
   extra DLL) fails verification, the client shows "The client is damaged",
   then deliberately faults at `MHYPBase.dll+0x18F8BAE`.
   Fix: `patch/` includes a `WinVerifyTrust` shim that returns success for
   game-directory files. Verified with a tracer build first (MessageBox /
   TaskDialog / exit / VEH hooks + module map dumper).
2. **SDK curl bypasses URL rewrites**: `loginByPassword` goes through the
   SDK's statically-linked curl (`HoYoNetworkSDK.dll`), which the classic
   Unity/WinHTTP redirect patches never see. With any system proxy/TUN it
   ends up at the real miHoYo servers.
   Fix: `patch/` rewrites those hostnames to `127.0.0.1` in `getaddrinfo`,
   and `tlsfront` terminates TLS on `127.0.0.1:443` (locally-trusted CA)
   and forwards plain HTTP to `127.0.0.1:8088`.
3. **Missing `rsa_key`**: HYPass reads `rsa_key` (OpenSSL PEM) from SDK
   config and encrypts credentials with it. Unregistered `hk4e_cn` paths
   fall into `UnhandledRequestRouter` which returns empty `{}`, so the
   client falls back to its hardcoded official key and login can never
   decrypt (`-10`). Fix is server-side (see fork branch).

## Layout

```
patch/      Rust cdylib, deployed as dbghelp.dll next to YuanShen.exe
            (app-dir DLL hijack; dbghelp is imported by the exe and is NOT
            in KnownDLLs). Forwards 252 exports to System32 dbghelp.
tlsfront/   Rust TLS terminator 127.0.0.1:443 -> 127.0.0.1:8088.
scripts/    start-lunagc.cmd/.ps1, create-account.ps1, stop-and-patch.ps1
```

## Build

Rust nightly (the patch uses `#![feature]`):

```
cd patch && cargo +nightly build --release     # -> target/release/dbghelp.dll
cd ../tlsfront && cargo build --release        # -> target/release/tlsfront.exe
```

JDK 17 + MongoDB for the server, see the LunaGC README
(`gradlew jar -PskipHandbook=1`).

## Deploy

1. Back up `GenshinImpact_Data/Plugins/Astrolabe.dll` (keep the game stock).
2. Copy `dbghelp.dll` next to `YuanShen.exe`.
3. Create a CA covering the SDK hosts, trust it for the current user, export
   `front.pfx` (see below), run `tlsfront.exe front.pfx <pfx-pass> <user> <pass>`.
4. Start MongoDB + `LunaGC-7.1.0.jar`, create an account, launch the game.

Self-signed CA (PowerShell, no admin needed for CurrentUser stores):

```powershell
$dns = @("passport-api.mihoyo.com","passport-api.miyoushe.com",
  "hk4e-sdk-s.mihoyo.com","hk4e-sdk.mihoyo.com","sdk-static.mihoyo.com",
  "public-data-api.mihoyo.com","data-abtest-api.mihoyo.com")
$cert = New-SelfSignedCertificate -DnsName $dns `
  -CertStoreLocation "Cert:\CurrentUser\My" -KeyAlgorithm RSA -KeyLength 2048 `
  -HashAlgorithm SHA256 -Type Custom -KeyUsage DigitalSignature,CertSign `
  -NotAfter (Get-Date).AddYears(5)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","CurrentUser")
$store.Open("ReadWrite"); $store.Add($cert); $store.Close()
$pass = ConvertTo-SecureString -String "lunagc" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "front.pfx" -Password $pass
```

Notes:

- `tlsfront`'s 3rd/4th args are the account credentials it substitutes for
  whatever ciphertext the client sends (the 7.1 SDK ignores the served
  `rsa_key`; the server accepts printable plaintext via its fallback path).
  Change them if you use a different account.
- `scripts/*.ps1` are ASCII-only on purpose: Windows PowerShell 5.1 parses
  BOM-less scripts as GBK and mangles non-ASCII comments.
- The game directory must keep the stock `Astrolabe.dll` (MDK checks it).

## Credits

- `patch/` derives from `capyb2222/animegamepatch` (itself from kitkat's
  `hk4e-patch-universal` and xeondev's original), plus tracer/bypass work.
- Server fork: `capyb2222/LunaGC_7.1.0` (fork of `girluh/LunaGC`),
  itself a Grasscutters lineage project (AGPL-3.0).
