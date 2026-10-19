# Threat model

## Protected assets

- the user's live WGS tree and recoverable backup history;
- package-debug ownership and cleanup state;
- the exact suspended title process selected for patching;
- the integrity of supported build profiles and the native helper;
- account privacy in normal logs and exported diagnostics.

## Trust boundaries

The controller and callback run at medium integrity. Their private base,
run directories, journal, result, claim, and helper are restricted to the
current user, SYSTEM, and Administrators with inheritance disabled. Windows
supplies the callback PID/TID. The installed Store package and System32
RuntimeBroker cross separate Windows-managed trust boundaries.

An administrator, SYSTEM, a compromised kernel, a compromised Windows package
service, or a malicious replacement of the entire release is outside the
local ACL threat model. Release signing and published hashes are distribution
controls, not protection against a fully compromised machine.

## Primary attacks and controls

| Threat | Control |
|---|---|
| Wrong/future game build | Exact package/profile/hash/PE/context matching; fail closed |
| Localized or renamed shortcut | Shell Link header plus exactly one embedded expected AUMID; exactly one match |
| PID reuse or callback spoof | PID, TID, process/helper creation time, session, package and file identity binding |
| RuntimeBroker confused with title | Exact System32 file identity plus package/process classification |
| Journal replay or duplicate callback | Nonce, controller identity, stage machine and atomic CREATE_NEW claim |
| TOCTOU in run files | Private non-reparse directories, atomic files, repeat identity checks |
| Partial patch or tampering | Suspend-count proof, context checks, cache flush and continuous patch monitor |
| Controller/helper crash | Durable stages and explicit recovery; no blind DisableDebugging call |
| Save mutation during backup | Snapshot before/after copy plus independent copy hash verification |
| Late WGS metadata update | Stability timer resets on every change; 30-second uninterrupted window |
| Cloud conflict | No restore/delete/reset; explicit warning that local settle is not server acknowledgement |
| Privacy leak | Support bundle exports aggregate state only; backups remain local |

## Non-goals

- bypassing licenses, entitlement, DRM, anti-cheat, or account authentication;
- patching unknown binaries by byte scanning;
- proving Microsoft's remote cloud acknowledgement from local files;
- repairing Xbox/Gaming Services by silently changing services or networking;
- guaranteeing operation on modified Windows installations or future builds.

## Recovery invariant

`DisableDebugging` is called only when the journal proves this run successfully
owned the matching enable operation. Ambiguous enable windows are retained for
manual inspection. Recovery authenticates the package, run directory, staged
binary, journal identity, process identity, and at-most-once cleanup state.
