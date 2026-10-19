# Validation status

Last updated: 2026-10-19 (Europe/Brussels).

## Completed

- Reference V9 source and binary hashes matched the handoff.
- Standalone native build passed MSVC 2019 x64 C++17 `/W4 /WX /Brepro`.
- Two independent `/Brepro` builds were byte-identical.
- Native inert self-test passed.
- PowerShell 5.1 parsing and wrapper self-test passed.
- WinForms GUI compiled for x64 with warning level 4 and warnings as errors.
- GUI companion-file self-test and a real rendered-window layout review passed.
- Default, minimum-width, status, action, activity-log and recovery-control
  states were reviewed without starting a game session.
- The GUI's primary action completed the real read-only check, displayed its
  explicit play confirmation, and returned to `No play session was started`
  when cancelled.
- An intentionally incomplete companion set disabled every action, showed the
  repair instruction and still allowed the window to close normally.
- Per-user install, GUI shortcut target, installed companion self-test and
  uninstall passed; uninstall preserved the existing backup store.
- The GitHub-ready Windows ZIP was produced after full repository-manifest
  verification; its external checksum, 15 packaged files, internal manifest
  and packaged GUI companion self-test passed.
- Synthetic empty, multi-directory, Unicode and changed-payload WGS cases passed.
- Trusted-profile tamper detection passed.
- Read-only package/build/signature/block-map/shortcut/service/network check
  passed on Windows build 26200.9711.
- Search audit found no personal path, XUID, old recovery nonce, fixed drive, or
  private save hash in public source/docs.

## Required before stable release

- `/analyze` build on the final source and independent source review;
- inert ACL/reparse/TOCTOU and crash-window fixture expansion;
- clean install/uninstall test under long Unicode user paths;
- keyboard-only, high-DPI and Windows display-scaling accessibility review;
- supported Windows 10 and Windows 11 test systems;
- system-drive and alternate-drive Store installations;
- English and non-English Windows/Xbox app;
- real standalone play/save test with independent backups;
- Xbox-to-PC, PC-to-Xbox, and Xbox-to-PC round trip;
- offline, mid-session network loss and late cloud-settle tests;
- code signing and release artifact verification.

No stable-release claim should be made until these items are recorded.
