// SPDX-License-Identifier: MIT
// Native-looking Windows Forms front end for the fail-closed PowerShell
// controller. Security decisions remain in sow_compat.ps1 and g.exe.

using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SowCompat
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 1 && String.Equals(args[0], "--self-test", StringComparison.Ordinal))
                return RunSelfTest(AppDomain.CurrentDomain.BaseDirectory);
            if (args.Length == 2 && String.Equals(args[0], "--self-test-root", StringComparison.Ordinal))
                return RunSelfTest(Path.GetFullPath(args[1]));

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainWindow());
            return 0;
        }

        private static int RunSelfTest(string root)
        {
            string[] required = {
                "sow_compat.ps1",
                "g.exe",
                Path.Combine("profiles", "sow-msstore-x64-1.0.28.2.json")
            };
            foreach (string relative in required)
            {
                string path = Path.Combine(root, relative);
                if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    return 10;
            }
            string script = File.ReadAllText(Path.Combine(root, "sow_compat.ps1"), Encoding.UTF8);
            if (!script.Contains("[switch]$CheckOnly") || !script.Contains("[switch]$Play") ||
                !script.Contains("[switch]$Recover") || !script.Contains("SOWC_UNSUPPORTED_BUILD"))
                return 11;
            return 0;
        }
    }

    internal sealed class MainWindow : Form
    {
        private const string UiVersion = "10.0.0-preview.3";
        private readonly Color Navy = Color.FromArgb(24, 35, 50);
        private readonly Color Blue = Color.FromArgb(29, 103, 192);
        private readonly Color Green = Color.FromArgb(25, 135, 84);
        private readonly Color Amber = Color.FromArgb(190, 112, 0);
        private readonly Color Red = Color.FromArgb(190, 45, 54);
        private readonly Color Surface = Color.White;
        private readonly Color Canvas = Color.FromArgb(244, 246, 249);

        private readonly string appRoot;
        private readonly string scriptPath;
        private readonly string privateRoot;
        private readonly string journalPath;
        private readonly string backupRoot;
        private readonly string supportRoot;
        private readonly string powershellPath;

        private readonly Label statusDot;
        private readonly Label statusTitle;
        private readonly Label statusDetail;
        private readonly Button playButton;
        private readonly Button prepareButton;
        private readonly Button recoverButton;
        private readonly Button backupsButton;
        private readonly Button supportButton;
        private readonly Button installButton;
        private readonly TextBox logBox;
        private readonly Label safetyLabel;
        private readonly StringBuilder runOutput = new StringBuilder();

        private Process currentProcess;
        private bool busy;
        private string lastOperationOutput = String.Empty;

        internal MainWindow()
        {
            appRoot = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            scriptPath = Path.Combine(appRoot, "sow_compat.ps1");
            privateRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SowCompat");
            journalPath = Path.Combine(privateRoot, "active.journal");
            backupRoot = Path.Combine(privateRoot, "backups");
            supportRoot = Path.Combine(privateRoot, "support");
            powershellPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe");

            Text = "Shadow of War Compatibility";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(920, 650);
            Size = new Size(920, 720);
            BackColor = Canvas;
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            Icon = SystemIcons.Application;

            Panel header = new Panel {
                Dock = DockStyle.Top,
                Height = 106,
                BackColor = Navy,
                Padding = new Padding(28, 20, 28, 16)
            };
            Label title = new Label {
                Text = "Shadow of War Compatibility",
                ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 20F),
                AutoSize = true,
                Location = new Point(26, 18)
            };
            Label subtitle = new Label {
                Text = "Safe launcher for the Microsoft Store / Xbox app edition",
                ForeColor = Color.FromArgb(205, 214, 225),
                Font = new Font("Segoe UI", 10F),
                AutoSize = true,
                Location = new Point(29, 61)
            };
            Label version = new Label {
                Text = UiVersion,
                ForeColor = Color.FromArgb(170, 184, 201),
                AutoSize = true,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Location = new Point(810, 24)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);
            header.Controls.Add(version);
            header.Resize += delegate { version.Left = header.ClientSize.Width - version.Width - 28; };
            Controls.Add(header);

            Panel content = new Panel {
                Dock = DockStyle.Fill,
                Padding = new Padding(26, 22, 26, 18),
                BackColor = Canvas
            };
            Controls.Add(content);
            content.BringToFront();

            Panel statusCard = new Panel {
                BackColor = Surface,
                Location = new Point(26, 22),
                Height = 108,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            statusCard.Width = content.ClientSize.Width - 52;
            content.Controls.Add(statusCard);

            statusDot = new Label {
                Text = "●",
                ForeColor = Blue,
                Font = new Font("Segoe UI", 22F),
                AutoSize = true,
                Location = new Point(22, 25)
            };
            statusTitle = new Label {
                Text = "Ready for a safety check",
                ForeColor = Navy,
                Font = new Font("Segoe UI Semibold", 13F),
                AutoSize = true,
                Location = new Point(65, 22)
            };
            statusDetail = new Label {
                Text = "The game will not start until all checks and the pre-run backup succeed.",
                ForeColor = Color.FromArgb(85, 95, 108),
                Font = new Font("Segoe UI", 9.5F),
                AutoEllipsis = true,
                Location = new Point(67, 54),
                Size = new Size(statusCard.Width - 92, 38),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            statusCard.Controls.Add(statusDot);
            statusCard.Controls.Add(statusTitle);
            statusCard.Controls.Add(statusDetail);

            playButton = CreateButton("Check & Play", Blue, Color.White, 26, 148, 170, 44);
            playButton.Click += PlayButtonClick;
            content.Controls.Add(playButton);

            prepareButton = CreateButton("Prepare backup", Color.White, Navy, 207, 148, 150, 44);
            prepareButton.FlatAppearance.BorderColor = Color.FromArgb(190, 198, 208);
            prepareButton.Click += PrepareButtonClick;
            content.Controls.Add(prepareButton);

            recoverButton = CreateButton("Recover", Color.White, Red, 368, 148, 115, 44);
            recoverButton.FlatAppearance.BorderColor = Color.FromArgb(220, 160, 164);
            recoverButton.Click += RecoverButtonClick;
            content.Controls.Add(recoverButton);

            backupsButton = CreateButton("Backups", Color.White, Navy, 494, 148, 110, 44);
            backupsButton.FlatAppearance.BorderColor = Color.FromArgb(190, 198, 208);
            backupsButton.Click += delegate { OpenFolder(backupRoot, "No backups have been created yet."); };
            content.Controls.Add(backupsButton);

            supportButton = CreateButton("Create support ZIP", Color.White, Navy, 615, 148, 140, 44);
            supportButton.FlatAppearance.BorderColor = Color.FromArgb(190, 198, 208);
            supportButton.Click += SupportButtonClick;
            content.Controls.Add(supportButton);

            installButton = CreateButton("Install shortcut", Color.White, Navy, 766, 148, 130, 44);
            installButton.FlatAppearance.BorderColor = Color.FromArgb(190, 198, 208);
            installButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            installButton.Click += InstallButtonClick;
            content.Controls.Add(installButton);

            Label activity = new Label {
                Text = "Activity",
                ForeColor = Navy,
                Font = new Font("Segoe UI Semibold", 11F),
                AutoSize = true,
                Location = new Point(27, 214)
            };
            content.Controls.Add(activity);

            logBox = new TextBox {
                Location = new Point(26, 242),
                Size = new Size(content.ClientSize.Width - 52, content.ClientSize.Height - 326),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(252, 253, 254),
                ForeColor = Color.FromArgb(40, 48, 57),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9F),
                WordWrap = true
            };
            content.Controls.Add(logBox);

            safetyLabel = new Label {
                Text = "No game-file patching, save restore, service changes, or telemetry. Local WGS stability is not a cloud acknowledgement.",
                ForeColor = Color.FromArgb(91, 101, 114),
                AutoEllipsis = true,
                Location = new Point(28, content.ClientSize.Height - 62),
                Size = new Size(content.ClientSize.Width - 56, 36),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            content.Controls.Add(safetyLabel);

            content.Resize += delegate {
                statusCard.Width = content.ClientSize.Width - 52;
                installButton.Left = content.ClientSize.Width - installButton.Width - 26;
            };

            FormClosing += WindowClosing;
            Shown += delegate { InitializeState(); };
        }

        private Button CreateButton(string text, Color background, Color foreground,
                                    int left, int top, int width, int height)
        {
            return new Button {
                Text = text,
                BackColor = background,
                ForeColor = foreground,
                FlatStyle = FlatStyle.Flat,
                FlatAppearance = { BorderSize = background == Color.White ? 1 : 0 },
                Cursor = Cursors.Hand,
                Location = new Point(left, top),
                Size = new Size(width, height),
                Font = new Font("Segoe UI Semibold", 9.5F),
                UseVisualStyleBackColor = false
            };
        }

        private void InitializeState()
        {
            if (!File.Exists(scriptPath) || !File.Exists(powershellPath))
            {
                SetStatus(Red, "Installation is incomplete",
                    "Keep SowCompat.exe, sow_compat.ps1, g.exe, and profiles together.");
                playButton.Enabled = false;
                prepareButton.Enabled = false;
                recoverButton.Enabled = false;
                backupsButton.Enabled = false;
                supportButton.Enabled = false;
                installButton.Enabled = false;
                return;
            }
            AppendLog("Ready. Click Check & Play for the normal guarded flow.");
            RefreshRecoveryState();
        }

        private void RefreshRecoveryState()
        {
            bool recovery = File.Exists(journalPath);
            recoverButton.Enabled = recovery && !busy;
            if (recovery)
            {
                SetStatus(Red, "Recovery required",
                    "A previous owned package-debug journal is still active. Run Recover before playing.");
                playButton.Enabled = false;
                prepareButton.Enabled = false;
            }
            else if (!busy)
            {
                recoverButton.Enabled = false;
                playButton.Enabled = true;
                prepareButton.Enabled = true;
            }
        }

        private async void PlayButtonClick(object sender, EventArgs e)
        {
            int check = await RunScriptAsync("-CheckOnly", "Checking game and Xbox services…");
            if (check != 0) return;
            DialogResult answer = MessageBox.Show(this,
                "All safety checks passed. The tool will create a verified backup, open the Xbox app, and wait for you to click Play.\n\nContinue?",
                "Ready to play", MessageBoxButtons.OKCancel, MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button1);
            if (answer != DialogResult.OK)
            {
                SetStatus(Blue, "Checks passed", "No play session was started.");
                return;
            }
            int play = await RunScriptAsync("-Play", "Preparing and monitoring the play session…");
            if (play == 0)
                SetStatus(Green, "Play session complete",
                    "The title exited, cleanup completed, and the stable local save was backed up.");
        }

        private async void PrepareButtonClick(object sender, EventArgs e)
        {
            int result = await RunScriptAsync("-PrepareOnly", "Checking and creating a verified backup…");
            if (result == 0)
                SetStatus(Green, "Backup prepared", "The game was not started and package debugging was not enabled.");
        }

        private async void RecoverButtonClick(object sender, EventArgs e)
        {
            DialogResult answer = MessageBox.Show(this,
                "Recovery will act only on the authenticated journal owned by this tool. Continue?",
                "Recover previous session", MessageBoxButtons.OKCancel,
                MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.OK) return;
            int result = await RunScriptAsync("-Recover", "Recovering the owned package-debug state…");
            if (result == 0)
                SetStatus(Green, "Recovery complete", "The owned package-debug state was cleaned up.");
        }

        private async void SupportButtonClick(object sender, EventArgs e)
        {
            DateTime startedUtc = DateTime.UtcNow;
            string temporaryLog = null;
            string action = "-ExportSupportBundle";
            try
            {
                if (!String.IsNullOrWhiteSpace(lastOperationOutput))
                {
                    temporaryLog = Path.Combine(Path.GetTempPath(),
                        "SowCompat-activity-" + Guid.NewGuid().ToString("N") + ".txt");
                    File.WriteAllText(temporaryLog, RedactSupportText(lastOperationOutput),
                        new UTF8Encoding(false));
                    action += " -ActivityLogPath \"" + temporaryLog.Replace("\"", "\"\"") + "\"";
                }
                int result = await RunScriptAsync(action, "Creating a privacy-redacted support ZIP…");
                if (result != 0) return;

                string newestBundle = FindNewestSupportBundle(startedUtc.AddSeconds(-5));
                SetStatus(Green, "Support ZIP ready",
                    "Review the ZIP, then drag it into a GitHub bug report. Nothing was uploaded automatically.");
                if (newestBundle != null)
                {
                    OpenFileInFolder(newestBundle);
                    MessageBox.Show(this,
                        "The privacy-redacted support ZIP is selected in File Explorer.\n\n" +
                        "Review it if you want, then drag the ZIP into a new bug report at:\n" +
                        "https://github.com/drnkPirate/sow-compat/issues/new?template=bug_report.yml\n\n" +
                        "Nothing was uploaded automatically.",
                        "Support ZIP ready", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    OpenFolder(supportRoot, null);
                }
            }
            finally
            {
                if (temporaryLog != null)
                {
                    try { if (File.Exists(temporaryLog)) File.Delete(temporaryLog); }
                    catch { }
                }
            }
        }

        private async void InstallButtonClick(object sender, EventArgs e)
        {
            int result = await RunScriptAsync("-Install", "Installing the per-user app and desktop shortcut…");
            if (result == 0)
                SetStatus(Green, "Shortcut installed", "Use Shadow of War Compatibility on your desktop from now on.");
        }

        private async Task<int> RunScriptAsync(string action, string runningMessage)
        {
            if (busy) return 254;
            if (!File.Exists(scriptPath))
            {
                SetStatus(Red, "Controller missing", "sow_compat.ps1 was not found beside this application.");
                return 253;
            }

            SetBusy(true);
            runOutput.Clear();
            AppendLog("");
            AppendLog("> " + action);
            SetStatus(Amber, runningMessage, "Keep this window open until the operation finishes.");

            ProcessStartInfo start = new ProcessStartInfo {
                FileName = powershellPath,
                Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                    scriptPath.Replace("\"", "\"\"") + "\" " + action,
                WorkingDirectory = appRoot,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            int exitCode;
            try
            {
                using (Process process = new Process())
                {
                    currentProcess = process;
                    process.StartInfo = start;
                    process.OutputDataReceived += delegate(object s, DataReceivedEventArgs a) {
                        if (a.Data != null) { runOutput.AppendLine(a.Data); AppendLog(a.Data); }
                    };
                    process.ErrorDataReceived += delegate(object s, DataReceivedEventArgs a) {
                        if (a.Data != null) { runOutput.AppendLine(a.Data); AppendLog(a.Data); }
                    };
                    if (!process.Start()) throw new InvalidOperationException("Windows PowerShell could not be started.");
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    exitCode = await Task.Run(delegate { process.WaitForExit(); return process.ExitCode; });
                    process.WaitForExit();
                }
            }
            catch (Exception exception)
            {
                runOutput.AppendLine(exception.Message);
                AppendLog("Launcher error: " + exception.Message);
                exitCode = 252;
            }
            finally
            {
                currentProcess = null;
                SetBusy(false);
            }

            AppendLog("Exit code: " + exitCode);
            if (!action.StartsWith("-ExportSupportBundle", StringComparison.Ordinal))
                lastOperationOutput = runOutput.ToString();
            if (exitCode != 0) ShowFriendlyFailure(runOutput.ToString());
            else if (action == "-CheckOnly")
                SetStatus(Green, "All checks passed", "The installed package is supported and local prerequisites are ready.");
            RefreshRecoveryState();
            return exitCode;
        }

        private void ShowFriendlyFailure(string output)
        {
            if (output.Contains("SOWC_UNSUPPORTED_BUILD"))
                SetStatus(Red, "Unsupported game build", "Nothing was changed. A reviewed profile is required for this exact version.");
            else if (output.Contains("SOWC_PACKAGE_NOT_INSTALLED"))
                SetStatus(Red, "Game not found", "Install the official Microsoft Store / Xbox app edition first.");
            else if (output.Contains("SOWC_PACKAGE_STATUS_INCONSISTENT"))
                SetStatus(Red, "Windows package status is inconsistent", "Use Windows Repair for the game, then create a support ZIP if this continues.");
            else if (output.Contains("SOWC_PACKAGE_STATUS_NOT_OK") || output.Contains("SOWC_PACKAGE_STATUS_NOT_FOUND"))
                SetStatus(Red, "Windows package is not ready", "Repair or update the game in Windows/Xbox, then try again.");
            else if (output.Contains("SOWC_GAME_SHORTCUT_AMBIGUOUS_OR_MISSING"))
                SetStatus(Red, "Official game shortcut needed", "Create exactly one desktop shortcut from the Xbox app, then try again.");
            else if (output.Contains("SOWC_RECOVERY_REQUIRED"))
                SetStatus(Red, "Recovery required", "Use Recover before starting another session.");
            else if (output.Contains("SOWC_NETWORK_UNAVAILABLE"))
                SetStatus(Red, "Network unavailable", "Windows must report an active connection for the guarded cloud-save flow.");
            else if (output.Contains("SOWC_SERVICE_NOT_RUNNING") || output.Contains("SOWC_SERVICE_DISABLED"))
                SetStatus(Red, "Xbox service is not ready", "Open Gaming Services / Xbox troubleshooting; the tool did not change any service.");
            else if (output.Contains("SOWC_WGS_SETTLE_TIMEOUT"))
                SetStatus(Red, "Save did not become stable", "Nothing was restored. Keep the pre-run backup and inspect Xbox sync state.");
            else if (output.Contains("SOWC_ELEVATED_PROCESS_REJECTED"))
                SetStatus(Red, "Run as a normal user", "Close the elevated copy and start the app without Run as administrator.");
            else
                SetStatus(Red, "Operation stopped safely", "Nothing unsafe was attempted. Review the activity log or create a support report.");
        }

        private void SetBusy(bool value)
        {
            busy = value;
            playButton.Enabled = !value;
            prepareButton.Enabled = !value;
            recoverButton.Enabled = !value && File.Exists(journalPath);
            backupsButton.Enabled = !value;
            supportButton.Enabled = !value;
            installButton.Enabled = !value;
            UseWaitCursor = value;
        }

        private void SetStatus(Color color, string title, string detail)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<Color, string, string>(SetStatus), color, title, detail);
                return;
            }
            statusDot.ForeColor = color;
            statusTitle.Text = title;
            statusDetail.Text = detail;
        }

        private void AppendLog(string line)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<string>(AppendLog), line);
                return;
            }
            logBox.AppendText(line + Environment.NewLine);
            logBox.SelectionStart = logBox.TextLength;
            logBox.ScrollToCaret();
        }

        private void OpenFolder(string path, string missingMessage)
        {
            if (!Directory.Exists(path))
            {
                if (!String.IsNullOrEmpty(missingMessage))
                    MessageBox.Show(this, missingMessage, "Shadow of War Compatibility",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Process.Start(new ProcessStartInfo {
                FileName = "explorer.exe",
                Arguments = "\"" + path + "\"",
                UseShellExecute = true
            });
        }

        private static string RedactSupportText(string text)
        {
            if (String.IsNullOrEmpty(text)) return String.Empty;
            string safe = text.Replace("\0", String.Empty);
            string[] knownValues = {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.UserName,
                Environment.MachineName
            };
            string[] replacements = { "%USERPROFILE%", "%LOCALAPPDATA%", "%DESKTOP%", "<USER>", "<COMPUTER>" };
            for (int index = 0; index < knownValues.Length; index++)
            {
                if (!String.IsNullOrWhiteSpace(knownValues[index]))
                    safe = Regex.Replace(safe, Regex.Escape(knownValues[index]), replacements[index],
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }
            safe = Regex.Replace(safe,
                @"^.*\b(?:authorization|bearer|token|password|secret|cookie)\b.*$",
                "<REDACTED_SENSITIVE_LINE>", RegexOptions.IgnoreCase | RegexOptions.Multiline);
            safe = Regex.Replace(safe, "\\b[A-Z]:\\\\[^\\r\\n\\\"'<>|]*", "<PATH>", RegexOptions.IgnoreCase);
            safe = Regex.Replace(safe, "\\\\\\\\[^\\r\\n\\\"'<>|]*", "<UNC_PATH>");
            safe = Regex.Replace(safe, @"\bS-\d-\d+(?:-\d+){1,}\b", "<SID>");
            safe = Regex.Replace(safe, @"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                "<EMAIL>", RegexOptions.IgnoreCase);
            safe = Regex.Replace(safe, @"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP_ADDRESS>");
            safe = Regex.Replace(safe,
                @"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                "<GUID>", RegexOptions.IgnoreCase);
            safe = Regex.Replace(safe, @"\b[0-9a-f]{32,128}\b", "<REDACTED_HEX>", RegexOptions.IgnoreCase);
            safe = Regex.Replace(safe, @"\b\d{10,20}\b", "<ACCOUNT_ID>");
            safe = Regex.Replace(safe, @"[^\u0009\u000A\u000D\u0020-\u007E]", "?");
            if (safe.Length > 65536)
                safe = "[Earlier output omitted; final 65536 characters retained.]\r\n" +
                    safe.Substring(safe.Length - 65536);
            return safe.Trim();
        }

        private string FindNewestSupportBundle(DateTime notBeforeUtc)
        {
            if (!Directory.Exists(supportRoot)) return null;
            string newest = null;
            DateTime newestWrite = DateTime.MinValue;
            foreach (string path in Directory.GetFiles(supportRoot, "SowCompat-support-*.zip",
                SearchOption.TopDirectoryOnly))
            {
                FileInfo file = new FileInfo(path);
                if ((file.Attributes & FileAttributes.ReparsePoint) != 0 || file.LastWriteTimeUtc < notBeforeUtc)
                    continue;
                if (file.LastWriteTimeUtc > newestWrite)
                {
                    newest = file.FullName;
                    newestWrite = file.LastWriteTimeUtc;
                }
            }
            return newest;
        }

        private void OpenFileInFolder(string path)
        {
            Process.Start(new ProcessStartInfo {
                FileName = "explorer.exe",
                Arguments = "/select,\"" + path + "\"",
                UseShellExecute = true
            });
        }

        private void WindowClosing(object sender, FormClosingEventArgs e)
        {
            if (!busy) return;
            e.Cancel = true;
            MessageBox.Show(this,
                "An operation is still running. Keep this window open so cleanup and backup verification can finish.",
                "Operation in progress", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
