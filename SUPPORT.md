# Getting support

SowCompat can create a privacy-redacted support ZIP that is designed to be
attached to a public GitHub bug report.

## Create the ZIP

1. Leave SowCompat open after the problem occurs.
2. Click **Create support ZIP**.
3. Wait for File Explorer to select the new `SowCompat-support-*.zip` file.
4. You may open and inspect the ZIP before sharing it.
5. Create a [bug report](https://github.com/sacrezm/sow-compat/issues/new?template=bug_report.yml)
   and drag the ZIP into the report.

Nothing is uploaded automatically. The ZIP contains a structured system and
game-readiness report, the redacted output of the last GUI operation when
available, recent run-state summaries, sharing instructions, and checksums for
the files inside the bundle.

The exporter removes paths, user and computer names, account identifiers,
tokens, IP addresses, GUIDs, long hexadecimal identifiers, save names, save
hashes, and save contents. Redaction is deliberately conservative, so some
otherwise useful text may appear as a placeholder.

## Command-line alternative

Run the following from the extracted SowCompat folder:

```powershell
.\sow_compat.ps1 -ExportSupportBundle
```

The command prints the completed ZIP path. Bundles are stored under the
current user's private `%LOCALAPPDATA%\SowCompat\support` directory.

## Do not share

Never attach any of the following to a public issue:

- Xbox/WGS save files or folders;
- files copied from `WindowsApps`;
- screenshots showing account details;
- authentication tokens, cookies, email addresses, or Xbox identifiers;
- the private `active.journal` file or complete run directories.

For a suspected security vulnerability, use
[GitHub private vulnerability reporting](https://github.com/sacrezm/sow-compat/security/advisories/new)
instead of a public issue.
