# SowCompat

**SowCompat** is an open-source, fail-closed compatibility launcher for the
Microsoft Store/Xbox app version of *Middle-earth: Shadow of War* on Windows
10/11 x64.

The tool works around one reviewed legacy Store-account call that prevents the
game from reaching its normal Xbox Game Save provider. It changes five bytes
in the game process only, after exact package, signature, build, callback, PE,
and instruction-context validation. It never patches the installed game file.

## Status

This repository is a **preview**, not a broad production release. The engine
and profile are ready for inert review and check-only use. A real play run with
this new standalone package and the full Windows 10/11 plus Xbox round-trip
matrix still needs independent validation before a stable GitHub release.

Supported profile:

| Profile | Package version | Architecture | Validation |
|---|---:|---|---|
| `sow-msstore-x64-1.0.28.2` | 1.0.28.2 | x64 | Original V9 play/save proof; standalone check-only passed on Windows build 26200.9711 |

Every other package or binary is `SOWC_UNSUPPORTED_BUILD`. There is no
signature scan or “best effort” patch path.

## Quick start

1. Download the release ZIP from GitHub and extract the complete folder.
2. In the Xbox app, create exactly one desktop shortcut for *Shadow of War*.
3. Double-click **SowCompat.exe** as a normal user. Do not use
   **Run as administrator**.
4. Click **Check & Play**. The app checks the exact game build and Xbox
   prerequisites before it offers to continue.
5. Confirm the prompt, then click **Play** once in the Xbox app when asked.

Keep all extracted files and the `profiles` folder together. The GUI creates a
verified pre-run backup before any play session and keeps the activity log
visible throughout cleanup and the post-run backup. Unsupported or ambiguous
states stop safely without modifying the installed game.

Click **Install shortcut** once if you want a permanent per-user copy. It is
installed under `%LOCALAPPDATA%\SowCompat\app` and a
`Shadow of War Compatibility` shortcut is added to the current user's desktop.
No administrator access is required.

The GUI also exposes **Prepare backup**, **Recover**, **Backups**, and a
privacy-redacted **Support report**. Recovery is enabled only when an owned,
unfinished journal exists.

## Advanced command-line use

Windows PowerShell 5.1 commands remain available for review and automation:

```powershell
.\sow_compat.ps1 -SelfTest
.\sow_compat.ps1 -CheckOnly
.\sow_compat.ps1 -PrepareOnly
```

`-SelfTest` is synthetic and inert. `-CheckOnly` reads package and health
metadata. `-PrepareOnly` additionally creates a verified local WGS backup but
does not enable package debugging or start the game.

## Safety model

- exact, SHA-256-pinned build profiles only;
- Store package health, manifest, block map, Appx signature, signer, file size,
  encrypted status, PE header, and three instruction contexts are checked;
- callback PID/TID, creation times, session, package, image identity, controller,
  helper, and System32 RuntimeBroker are authenticated;
- one process-local five-byte patch is monitored until the exact title exits;
- journaled, at-most-once package-debug cleanup and explicit recovery;
- atomic pre-run and post-run WGS backups with source/copy revalidation;
- 30 seconds of uninterrupted stable local WGS state before post-run success;
- no automatic restore, delete, cloud reset, service change, registry change,
  firewall change, WindowsApps ACL change, telemetry, or upload.

Local WGS stability is not a Microsoft cloud-server acknowledgement. Cross-
device transfer must be verified separately, without simultaneous PC/Xbox play.

## Commands

| Command | Effect |
|---|---|
| `-SelfTest` | Native and synthetic WGS/profile tests; inert |
| `-CheckOnly` | Read-only package/build/service/network check |
| `-PrepareOnly` | Check plus verified pre-run backup |
| `-Play` | Full guarded session |
| `-Recover` | Recover an owned unresolved package-debug journal |
| `-ExportSupportBundle` | Create a redacted local JSON diagnostic |
| `-Install` | Per-user install and desktop launcher |
| `-Uninstall` | Remove app/launcher; preserve backups and evidence |

Use `-ExternalBackupRoot <existing-directory>` with `-PrepareOnly` or `-Play`
to copy a backup to a user-selected destination. No drive is assumed.

## Building

Visual Studio 2019 or newer Build Tools with the x64 C++ workload and the
Windows .NET Framework compiler are required:

```cmd
BUILD.cmd
BUILD.cmd --analyze
```

The native build uses C++17, `/W4 /WX /Brepro`; `--analyze` adds `/analyze`.
The WinForms GUI builds with warnings treated as errors and runs its companion-
file self-test. The reviewed native release hash was produced with Visual
Studio 2019. Other compiler versions may produce a different, untrusted native
development hash. Output is written under `build\`.
See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a new profile.

## Creating a release asset

Maintainers can create the end-user ZIP and its separate SHA-256 file with:

```powershell
.\PACK-RELEASE.ps1
```

The packager first verifies every entry in the repository's
`SHA256SUMS.txt`, rejects reparse files, then stages only the runtime,
profile, launcher, license and user/security documentation. Output is written
under `release\`. GitHub Actions performs the same packaging step and exposes
the ZIP and checksum as a build artifact; it does not publish a GitHub release
automatically.

## Privacy and support

Backups stay under `%LOCALAPPDATA%\SowCompat\backups`. Support bundles contain
counts and health state only—never XUID-like paths, tokens, save names, hashes,
or contents. See [SECURITY.md](SECURITY.md) for private vulnerability reports
and [THREAT-MODEL.md](THREAT-MODEL.md) for trust boundaries.

License: MIT. See [NOTICE.md](NOTICE.md) for trademark and affiliation terms.
