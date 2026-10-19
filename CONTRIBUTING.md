# Contributing

Contributions are welcome under the MIT license.

## Build profiles

A new profile must not be inferred on an end-user machine. Submit evidence for:

- official Store identity, publisher, architecture and exact version;
- manifest, block map, package signature, signer and full image hash;
- PE timestamp and `SizeOfImage`;
- exact patch RVA/original/replacement bytes and broad context;
- independent writer, delete and GameSave semantic anchors;
- accepted title exit codes and Windows builds tested;
- real pre/post save verification and PC-to-Xbox-to-PC round-trip results.

Profile JSON is data for review, not authority by itself. A maintainer must add
its SHA-256 to the wrapper and the same reviewed constants to the native
profile table, rebuild reproducibly, run static analysis, and publish hashes.

## Pull requests

Run `BUILD.cmd --analyze`, `powershell -File .\sow_compat.ps1 -SelfTest`, and
the check-only flow. Never commit WGS data, package files, game binaries,
account identifiers, tokens, private paths, crash dumps, or diagnostic bundles.
