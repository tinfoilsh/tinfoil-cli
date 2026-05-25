# Tinfoil Tray

A menu-bar / system-tray app that runs the verified [Tinfoil](https://tinfoil.sh) proxy on
`localhost`. The tray supervises a bundled `tinfoil` CLI subprocess, exposes start/stop and
verification details from the status bar, and is built with Electron + Vite + React.

The app is intentionally a thin wrapper around the CLI: all attestation, TLS pinning, and
request forwarding happen inside the same `tinfoil` binary you can run by hand from a terminal.

## Layout

```
tray/
  src/
    main/       Electron main process (proxy lifecycle, IPC, menu, popup, updater)
    preload/    contextBridge exposing a typed `window.tinfoil` API to the renderer
    renderer/   React popup UI + embedded verification-center iframe
  assets/       App and tray-status icons (PNG + macOS .icns)
  build/        Code-signing entitlements, .pkg postinstall, iconset source
  scripts/      Cross-compile + universal-binary helper for the bundled CLI
  resources/bin/  (gitignored) The `tinfoil` binary copied in at build time
```

## Requirements

- Node.js 20+
- Go 1.22+ (for cross-compiling the embedded `tinfoil` CLI)
- macOS 13+ recommended for development; Linux / Windows build paths exist but are less
  exercised locally

## Development

```bash
cd tray
npm install
npm run dev
```

`npm run dev` first cross-compiles the `tinfoil` binary into `resources/bin/`, then launches
the Electron app with hot-reload for the renderer.

### Useful scripts

| Script | Purpose |
|--------|---------|
| `npm run dev` | Build the CLI for the host OS and start Electron with hot-reload |
| `npm run build` | Production build of main + preload + renderer into `out/` |
| `npm run lint` | ESLint with `--max-warnings 0` |
| `npm run typecheck` | TypeScript projects for both Node and Web |
| `npm run build:cli` | Just rebuild the embedded `tinfoil` binary |
| `npm run package:mac` | Build signed + notarized macOS installers (`.pkg`, `.dmg`, `.zip`) |
| `npm run package:linux` | Build Linux installers (`.AppImage`, `.deb`) |
| `npm run package:win` | Build Windows installer (`.exe`, NSIS) |

## Packaging for distribution

`electron-builder` reads `electron-builder.yml`. The macOS configuration enables Apple's
Hardened Runtime, ships entitlements for V8 JIT and dynamic library loading, and runs
notarization at build time.

To produce a signed + notarized macOS release locally:

```bash
export CSC_LINK="$(base64 -i /path/to/DeveloperIDApplication.p12)"
export CSC_KEY_PASSWORD="…"
export CSC_INSTALLER_LINK="$(base64 -i /path/to/DeveloperIDInstaller.p12)"
export CSC_INSTALLER_KEY_PASSWORD="…"
export APPLE_ID="releases@example.com"
export APPLE_APP_SPECIFIC_PASSWORD="abcd-efgh-ijkl-mnop"
export APPLE_TEAM_ID="ABCDE12345"

npm run package:mac
```

If those env vars are absent, set `CSC_IDENTITY_AUTO_DISCOVERY=false` to produce an
unsigned build for smoke testing.

### App bundle layout (macOS)

```
/Applications/Tinfoil.app/
  Contents/
    MacOS/Tinfoil                 # Electron host
    Resources/
      bin/tinfoil                 # Universal (x64 + arm64) CLI binary
      app.asar                    # Renderer + main process bundle
      assets/icon-tray-*.png      # Menu-bar template icons
```

The `.pkg` installer drops the app into `/Applications` and runs `build/pkg-scripts/postinstall`,
which `open`s the app once so the tray shows up immediately.

## CI

Two GitHub Actions workflows live in `.github/workflows/`:

- `tray-test.yml` — runs on every PR / push touching `tray/**`; installs deps, lints,
  typechecks, and produces an unsigned production build on Ubuntu.
- `tray-release.yml` — runs on tag pushes (`v*`); builds, signs, and publishes installers for
  macOS / Linux / Windows to the GitHub release matching the tag.

The release workflow expects these repository secrets (only used on macOS):

| Secret | Purpose |
|--------|---------|
| `APPLE_CERTIFICATE_P12_BASE64` | Developer ID **Application** cert, base64 (`base64 -i cert.p12`) |
| `APPLE_CERTIFICATE_PASSWORD` | Password for the Application cert |
| `APPLE_INSTALLER_P12_BASE64` | Developer ID **Installer** cert, base64 |
| `APPLE_INSTALLER_PASSWORD` | Password for the Installer cert |
| `APPLE_ID` | Apple ID email used for notarization |
| `APPLE_APP_SPECIFIC_PASSWORD` | App-specific password for notarytool |
| `APPLE_TEAM_ID` | 10-character Apple developer team ID |

`GH_TOKEN` is wired automatically from `secrets.GITHUB_TOKEN`.

## Auto-updates

The packaged app polls GitHub Releases every 6 hours via `electron-updater` and prompts the
user when a new build is available. `.deb` installs do not receive auto-updates; users on
that target must reinstall the latest `.deb` manually. AppImage and macOS `.zip` / `.dmg`
update in-place.

## Security notes

- The renderer runs sandboxed: `contextIsolation: true`, `sandbox: true`,
  `nodeIntegration: false`. All renderer → main calls go through a typed preload bridge.
- The popup HTML ships a strict Content-Security-Policy header that only allows the
  verification-center iframe to load from `https://verification-center.tinfoil.sh`.
- The iframe itself is restricted with `sandbox="allow-scripts allow-same-origin"` and a
  no-referrer policy.
- The macOS app runs under Hardened Runtime with notarization enabled by default;
  unsigned builds are only produced when `CSC_IDENTITY_AUTO_DISCOVERY=false` is set.
