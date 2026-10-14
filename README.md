<p align="center">
  <strong>English</strong> | <a href="README.es.md">Español</a>
</p>

<p align="center">
  <img src="public/brand/DeamonizeLogo.png" alt="Deamonize" width="340" />
</p>

<h1 align="center">DEAMONIZE</h1>

<p align="center">
  <strong>SCAN · SECURE · PROTECT</strong>
</p>

<p align="center">
  Desktop security analyzer for Windows services.<br/>
  Classifies every service on your system as safe, suspicious, dangerous or unknown — 100% offline by default.
</p>

<p align="center">
  <a href="https://github.com/jupaman-GH/Deamonize/releases/latest"><img src="https://img.shields.io/github/v/release/jupaman-GH/Deamonize?style=flat-square&label=release" alt="Release" /></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square" alt="Platform" />
  <img src="https://img.shields.io/badge/Tauri-2-black?style=flat-square" alt="Tauri 2" />
  <img src="https://img.shields.io/badge/license-all%20rights%20reserved-lightgrey?style=flat-square" alt="License" />
</p>

---

## Overview

**Deamonize** is a frameless desktop application built with **Tauri 2** that inspects the services installed on your Windows machine and classifies each one with a local risk engine:

- **Local classification engine** — whitelist/blacklist rules, signer checks, binary heuristics (unsigned, lookalike names, unquoted paths, user-folder locations, PE spoofing) and SHA-256 hashing.
- **Staged external escalation** — when local confidence is low, it can consult **VirusTotal → Web search → AI** using your own API keys (optional, everything stays on your machine).
- **Rules editor** — manage whitelist, blacklist and greylist rules by name, path, signer or hash.
- **Cache & history** — results are cached with TTL, scans are persisted and can be diffed to spot changes between two points in time.
- **Exportable reports** — self-contained HTML (shareable) and machine-readable JSON with the evidence and sources of every verdict.
- **Modern UI** — custom frameless window with animated splash screen, dark/light themes, English/Spanish interface and a purple `DEAMONIZE` brand wordmark.

## Screenshots

| Dashboard | Services |
| :---: | :---: |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Services](docs/screenshots/services.png) |

| Settings |
| :---: |
| ![Settings](docs/screenshots/settings.png) |

## Automatic updates

Deamonize can update itself from this repository's **GitHub Releases**:

1. Open **Settings → Updates** and enable **Automatic updates**.
2. On every launch the app checks the latest release in the background and notifies you when a newer version is available.
3. You can also press **Check for updates** manually; the app downloads the installer and applies it.

Update packages are cryptographically signed, and the public key is embedded in the app — it will refuse to install anything unsigned.

## Install

Download and run the installer from the [latest release](https://github.com/jupaman-GH/Deamonize/releases/latest):

- `Deamonize_1.0.1_x64-setup.exe` — NSIS installer (per-user, recommended)
- `Deamonize_1.0.1_x64_en-US.msi` — MSI installer (for managed deployments)

> The installers are not code-signed yet, so Windows SmartScreen may show a warning. Choose *More info → Run anyway*.

## Tech stack

- **Frontend** — React 19, TypeScript, Vite, Tailwind CSS 4, shadcn/ui components
- **Backend** — Rust, Tauri 2, rusqlite (SQLite), `windows` crate for service enumeration & signature checks
- **Plugins** — `tauri-plugin-opener`, `tauri-plugin-updater` (GitHub Releases)

## Development

```bash
npm install
npm run tauri dev      # run the app in development mode
npm run tauri build    # produce installers + portable exe in src-tauri/target/release/bundle
```

Requirements: Node.js 18+, Rust (stable) and the Tauri 2 prerequisites for Windows.

## Donations

I am developing several more pieces of software that try to make everyone's
daily life easier. Every software under development will be free. Donating is
the real way for every coin the developer receives to be because they truly
deserve it, given voluntarily. THANK YOU!

[![ko-fi](Assets/logomarkLogo.Png)](https://ko-fi.com/friezasama) BUY ME A COFFEE

## Privacy

Deamonize works **100% offline** out of the box: scanning, classification, history and reports never touch the network. External lookups (VirusTotal / web search / AI) are strictly opt-in and only run when you configure your own API keys in **Settings**, which are stored locally on your device.

---

<p align="center">Made with Tauri · React · Rust</p>
