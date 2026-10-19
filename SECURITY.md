# Security policy

## Supported versions

Only the latest tagged release and the exact profiles listed in its README are
supported. Unknown package versions are intentionally unsupported.

## Reporting a vulnerability

Before publishing a report, remove usernames, XUIDs, tokens, absolute paths,
save contents, and save hashes. Prefer GitHub private vulnerability reporting
once the repository is published. Do not attach live WGS files to a public
issue.

Useful evidence is the privacy-redacted ZIP created by **Create support ZIP**
or `-ExportSupportBundle`. Nothing is uploaded automatically. Users can inspect
the ZIP before attaching it to a GitHub issue. See [SUPPORT.md](SUPPORT.md).

Do not test suspected issues against somebody's only save copy. Never weaken
WindowsApps ACLs, take ownership of package files, or force package-debug
cleanup without a matching owned journal.
