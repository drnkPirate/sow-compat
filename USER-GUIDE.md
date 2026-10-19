# Beginner's guide

This guide is for people who just want to play *Middle-earth: Shadow of War*
and do not normally work with technical tools.

## Before you start

You need:

- a Windows 10 or Windows 11 PC;
- the Microsoft Store/Xbox app version of *Middle-earth: Shadow of War*;
- the game installed through the Xbox app;
- an internet connection and the Xbox app signed in to the account that owns
  the game.

SowCompat currently supports only the exact game version listed in the main
[README](README.md). If your version is different, SowCompat stops safely and
does not change the game.

## Download and open SowCompat

1. Open the [latest releases page](https://github.com/drnkPirate/sow-compat/releases).
2. Open the newest release marked **Pre-release**.
3. Under **Assets**, click the file whose name ends in `win-x64.zip`.
   Do not download the file ending in `.sha256`; that file is only for people
   who want to verify the download.
4. Open your **Downloads** folder.
5. Right-click the downloaded ZIP file and choose **Extract All**.
6. Open the extracted folder. Keep every file and the `profiles` folder
   together.
7. Double-click **SowCompat.exe**. Use it as a normal user; do not choose
   **Run as administrator**.

If Windows shows a security warning, confirm that the publisher is unknown
only because this open-source preview is not code-signed. Choose **More info**
and then **Run anyway** only if the file came from this repository's official
release page. If you are unsure where the file came from, cancel.

## Play the game

1. Open the Xbox app and make sure you are signed in.
2. In the Xbox app, create one desktop shortcut for *Shadow of War* if you do
   not already have one.
3. In SowCompat, click **Check & Play**.
4. Wait while the checks run. Read the message and confirm when SowCompat asks
   whether you want to continue.
5. When instructed, return to the Xbox app and click **Play** once.
6. Play normally. Keep SowCompat open while the game is running.
7. Exit the game normally and allow SowCompat to finish its cleanup and backup.

SowCompat creates a backup before the game starts. It stops without changing
the installed game whenever a required check fails.

## Optional: install a desktop shortcut

Click **Install shortcut** in SowCompat if you want a permanent desktop
shortcut. This installs only for your Windows account and does not need
administrator access.

## If something goes wrong

Do not reinstall Windows, delete saves, change WindowsApps permissions, or
reset Xbox cloud data.

Instead:

1. Leave SowCompat open after the error.
2. Click **Create support ZIP**.
3. Wait for File Explorer to select a file named `SowCompat-support-....zip`.
4. You can open the ZIP to inspect its contents before sharing it.
5. Open the [bug-report form](https://github.com/drnkPirate/sow-compat/issues/new?template=bug_report.yml).
6. Describe what you clicked and what happened in simple words.
7. Drag the support ZIP into the report and submit it.

Nothing is uploaded automatically. SowCompat removes common personal details
from the support bundle, including usernames, paths, account identifiers,
email addresses, IP addresses, and tokens. Never upload Xbox save files.

For more detail, see [Getting support](SUPPORT.md).
