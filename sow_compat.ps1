[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(ParameterSetName = 'Play')][switch]$Play,
    [Parameter(ParameterSetName = 'Check')][switch]$CheckOnly,
    [Parameter(ParameterSetName = 'Prepare')][switch]$PrepareOnly,
    [Parameter(ParameterSetName = 'Recover')][switch]$Recover,
    [Parameter(ParameterSetName = 'SelfTest')][switch]$SelfTest,
    [Parameter(ParameterSetName = 'Support')][switch]$ExportSupportBundle,
    [Parameter(ParameterSetName = 'Support')][string]$ActivityLogPath,
    [Parameter(ParameterSetName = 'Install')][switch]$Install,
    [Parameter(ParameterSetName = 'Uninstall')][switch]$Uninstall,
    [Parameter(ParameterSetName = 'Play')]
    [Parameter(ParameterSetName = 'Prepare')]
    [string]$ExternalBackupRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:ToolVersion = '10.0.0-preview.3'
$script:BaseRoot = Join-Path $env:LOCALAPPDATA 'SowCompat'
$script:BackupRoot = Join-Path $script:BaseRoot 'backups'
$script:SupportRoot = Join-Path $script:BaseRoot 'support'
$script:GatePath = Join-Path $PSScriptRoot 'g.exe'
$script:ProfilesRoot = Join-Path $PSScriptRoot 'profiles'
$script:ExpectedGateSha256 = '156546013258D911509AA6E2AC5E7F7287BBB72546DA435272527EFC641F6D92'
$script:TrustedProfileHashes = @{
    'sow-msstore-x64-1.0.28.2' = 'CEC70AA49C9CDC6265C58B381D6274684188C34074E29C3A620E0EB8D0A65120'
}
$script:Selected = $null
$script:WgsRoot = $null

$requiredModules = @(
    (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1'),
    (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'),
    (Join-Path $PSHOME 'Modules\Appx\Appx.psd1')
)
foreach ($module in $requiredModules) {
    if (-not (Test-Path -LiteralPath $module -PathType Leaf)) { throw "SOWC_MISSING_WINDOWS_MODULE: $module" }
    Import-Module -Name $module -ErrorAction Stop
}

function Test-IsElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "SOWC_FILE_MISSING: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "SOWC_REPARSE_FILE_REJECTED: $Path" }
}

function Set-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($userSid)
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @($userSid, $systemSid, $adminsSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,
            [Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($Path, $security)
    Assert-PrivateDirectoryAcl -Path $Path
}

function Assert-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "SOWC_PRIVATE_DIRECTORY_INVALID: $Path"
    }
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $allowed = @($userSid.Value, 'S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw "SOWC_PRIVATE_ACL_INHERITS: $Path" }
    $seen = @{}
    foreach ($entry in @($acl.Access)) {
        $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($entry.IsInherited -or $entry.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $allowed -cnotcontains $sid -or
            (($entry.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
             [Security.AccessControl.FileSystemRights]::FullControl)) {
            throw "SOWC_PRIVATE_ACL_UNEXPECTED: $Path"
        }
        $seen[$sid] = $true
    }
    foreach ($sid in $allowed) { if (-not $seen.ContainsKey($sid)) { throw "SOWC_PRIVATE_ACL_MISSING: $Path" } }
}

function Initialize-PrivateRoot {
    if (-not (Test-Path -LiteralPath $script:BaseRoot -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $script:BaseRoot)
    }
    Set-PrivateDirectoryAcl -Path $script:BaseRoot
}

function Get-TrustedProfiles {
    if (-not (Test-Path -LiteralPath $script:ProfilesRoot -PathType Container)) { throw 'SOWC_PROFILE_DIRECTORY_MISSING' }
    $profiles = @()
    foreach ($path in @(Get-ChildItem -LiteralPath $script:ProfilesRoot -Filter '*.json' -File)) {
        Assert-RegularFile -Path $path.FullName
        $raw = [IO.File]::ReadAllText($path.FullName, [Text.Encoding]::UTF8)
        $profile = $raw | ConvertFrom-Json
        if ($null -eq $profile.id -or -not $script:TrustedProfileHashes.ContainsKey([string]$profile.id)) {
            throw "SOWC_UNTRUSTED_PROFILE: $($path.Name)"
        }
        $hash = (Get-FileHash -LiteralPath $path.FullName -Algorithm SHA256).Hash
        if ($hash -cne [string]$script:TrustedProfileHashes[[string]$profile.id]) {
            throw "SOWC_PROFILE_INTEGRITY_FAILED: $($profile.id)"
        }
        $required = @('schema','id','product_id','package_name','package_family_name','package_full_name',
            'publisher','publisher_id','architecture','version','application_id','aumid','entry_point',
            'relative_image_path','manifest_sha256','block_map_sha256','package_signature_sha256',
            'signer_thumbprint','image_sha256','image_size','block_count','pe_timestamp','size_of_image',
            'patch','semantic_anchors','accepted_exit_codes','minimum_windows_build','tested_windows_builds',
            'profile_version','author','evidence')
        $names = @($profile.PSObject.Properties.Name)
        foreach ($name in $required) { if ($names -cnotcontains $name) { throw "SOWC_PROFILE_SCHEMA_MISSING_${name}: $($profile.id)" } }
        if ([int]$profile.schema -ne 1 -or
            [string]$profile.package_family_name -notmatch '^[A-Za-z0-9.-]+_[A-Za-z0-9]+$' -or
            [string]$profile.relative_image_path -match '(^[\\/]|\.\.)' -or
            [string]$profile.image_sha256 -notmatch '^[0-9A-F]{64}$' -or
            [string]$profile.manifest_sha256 -notmatch '^[0-9A-F]{64}$' -or
            [string]$profile.patch.original -notmatch '^[0-9A-F]{10}$' -or
            [string]$profile.patch.replacement -cne '9090909090') { throw "SOWC_PROFILE_SCHEMA_INVALID: $($profile.id)" }
        $profiles += [pscustomobject]@{ Path = $path.FullName; Data = $profile; Hash = $hash }
    }
    if ($profiles.Count -eq 0) { throw 'SOWC_NO_TRUSTED_PROFILES' }
    return $profiles
}

function Select-InstalledProfile {
    $profiles = @(Get-TrustedProfiles)
    $families = @($profiles | ForEach-Object { [string]$_.Data.package_family_name } | Sort-Object -Unique)
    $packages = @(Get-AppxPackage -PackageTypeFilter Main | Where-Object { $families -ccontains [string]$_.PackageFamilyName })
    if ($packages.Count -eq 0) { throw 'SOWC_PACKAGE_NOT_INSTALLED' }
    $matches = @()
    foreach ($package in $packages) {
        foreach ($candidate in $profiles) {
            if ([string]$package.PackageFullName -ceq [string]$candidate.Data.package_full_name) {
                $matches += [pscustomobject]@{ Package = $package; Profile = $candidate }
            }
        }
    }
    if ($matches.Count -ne 1) {
        $versions = @($packages | ForEach-Object { [string]$_.Version }) -join ', '
        throw "SOWC_UNSUPPORTED_BUILD: installed version(s): $versions"
    }
    $script:Selected = $matches[0]
    $script:WgsRoot = Join-Path $env:LOCALAPPDATA ('Packages\' +
        [string]$script:Selected.Profile.Data.package_family_name + '\SystemAppData\wgs')
    return $script:Selected
}

function Get-PackageStatusSummary {
    param([Parameter(Mandatory = $true)]$Status)
    $summary = [ordered]@{
        verify_is_ok = [bool]$Status.VerifyIsOK()
        data_offline = [bool]$Status.DataOffline
        dependency_issue = [bool]$Status.DependencyIssue
        deployment_in_progress = [bool]$Status.DeploymentInProgress
        disabled = [bool]$Status.Disabled
        is_partially_staged = [bool]$Status.IsPartiallyStaged
        license_issue = [bool]$Status.LicenseIssue
        modified = [bool]$Status.Modified
        needs_remediation = [bool]$Status.NeedsRemediation
        not_available = [bool]$Status.NotAvailable
        package_offline = [bool]$Status.PackageOffline
        servicing = [bool]$Status.Servicing
        tampered = [bool]$Status.Tampered
    }
    $summary['failure_flags'] = @(Get-PackageStatusFailureNames -Summary $summary)
    return $summary
}

function Get-PackageStatusFailureNames {
    param([Parameter(Mandatory = $true)]$Summary)
    $names = @('data_offline','dependency_issue','deployment_in_progress','disabled',
        'is_partially_staged','license_issue','modified','needs_remediation',
        'not_available','package_offline','servicing','tampered')
    return @($names | Where-Object { [bool]$Summary[$_] })
}

function Assert-WinRtPackageStatus {
    param($Package)
    if ($null -eq $Package) { throw 'SOWC_PACKAGE_STATUS_NOT_FOUND' }
    $summary = Get-PackageStatusSummary -Status $Package.Status
    if ([bool]$summary.verify_is_ok) { return }
    $failures = @(Get-PackageStatusFailureNames -Summary $summary)
    if ($failures.Count -eq 0) {
        throw 'SOWC_PACKAGE_STATUS_INCONSISTENT: VerifyIsOK=False but no public failure flags are set; use Windows Repair and create a support ZIP'
    }
    throw "SOWC_PACKAGE_STATUS_NOT_OK: $($failures -join ',')"
}

function Invoke-WinRtBooleanOperation {
    param([Parameter(Mandatory = $true)]$Operation)
    $asTask = @([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -ceq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Length -eq 1 -and
        $_.GetParameters().Length -eq 1 -and $_.ReturnType.IsGenericType -and
        $_.ReturnType.GetGenericTypeDefinition() -eq [Threading.Tasks.Task``1]
    })
    if ($asTask.Count -ne 1) { throw 'SOWC_WINRT_TASK_BRIDGE_AMBIGUOUS' }
    $task = $asTask[0].MakeGenericMethod([bool]).Invoke($null, @($Operation))
    return [bool]$task.GetAwaiter().GetResult()
}

function Assert-PackageContentIntegrity {
    param([Parameter(Mandatory = $true)][string]$PackageFullName)
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $managerType = [Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]
    $manager = $managerType::new()
    $installed = $manager.FindPackageForUser([string]::Empty, $PackageFullName)
    Assert-WinRtPackageStatus -Package $installed
    if (-not (Invoke-WinRtBooleanOperation -Operation $installed.VerifyContentIntegrityAsync())) {
        throw 'SOWC_PACKAGE_CONTENT_INTEGRITY_FAILED'
    }
    $refreshed = $manager.FindPackageForUser([string]::Empty, $PackageFullName)
    Assert-WinRtPackageStatus -Package $refreshed
}

function Resolve-PackageContentRoot {
    param([Parameter(Mandatory = $true)]$Package)
    $logical = [IO.Path]::GetFullPath([string]$Package.InstallLocation).TrimEnd('\')
    if ((Split-Path -Leaf $logical) -cne [string]$Package.PackageFullName) { throw 'SOWC_INSTALL_LOCATION_IDENTITY_MISMATCH' }
    $item = Get-Item -LiteralPath $logical -Force
    if (-not $item.PSIsContainer) { throw 'SOWC_INSTALL_LOCATION_NOT_DIRECTORY' }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { return $logical }
    if ([string]$item.LinkType -cne 'Junction' -or @($item.Target).Count -ne 1) { throw 'SOWC_INSTALL_LOCATION_REPARSE_REJECTED' }
    $physical = [IO.Path]::GetFullPath([string]@($item.Target)[0]).TrimEnd('\')
    $physicalItem = Get-Item -LiteralPath $physical -Force
    if (-not $physicalItem.PSIsContainer -or (($physicalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        (Split-Path -Leaf $physical) -cne [string]$Package.PackageFullName) { throw 'SOWC_PHYSICAL_INSTALL_LOCATION_INVALID' }
    return $physical
}

function Assert-ManifestIdentity {
    param([string]$Path, $Profile)
    [xml]$xml = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $identity = $xml.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Identity']")
    $app = $xml.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Applications']/*[local-name()='Application' and @Id='$($Profile.application_id)']")
    if ($null -eq $identity -or $null -eq $app -or [string]$identity.Name -cne [string]$Profile.package_name -or
        [string]$identity.Publisher -cne [string]$Profile.publisher -or [string]$identity.Version -cne [string]$Profile.version -or
        [string]$identity.ProcessorArchitecture -cne 'x64' -or [string]$app.Executable -cne [string]$Profile.relative_image_path -or
        [string]$app.EntryPoint -cne [string]$Profile.entry_point) { throw 'SOWC_MANIFEST_IDENTITY_MISMATCH' }
}

function Assert-BlockMapImageRecord {
    param([string]$Path, $Profile)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $settings = New-Object Xml.XmlReaderSettings
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null; $settings.IgnoreWhitespace = $true
        $reader = [Xml.XmlReader]::Create($stream, $settings)
        try {
            $rootSeen = $false; $targetCount = 0; $inside = $false; $targetDepth = -1; $blocks = 0; $fileHashes = 0; $declared = $null
            while ($reader.Read()) {
                if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                    if ($reader.Depth -eq 0) {
                        if ($reader.LocalName -cne 'BlockMap' -or $reader.GetAttribute('HashMethod') -cne 'http://www.w3.org/2001/04/xmlenc#sha256') { throw 'SOWC_BLOCKMAP_ROOT_INVALID' }
                        $rootSeen = $true; continue
                    }
                    if ($reader.LocalName -ceq 'File') {
                        $inside = $false
                        if ($reader.GetAttribute('Name') -ceq [string]$Profile.relative_image_path) {
                            $targetCount++
                            if ($reader.GetAttribute('Size') -cne [string]$Profile.image_size -or $reader.GetAttribute('Encrypted') -cne 'true') { throw 'SOWC_BLOCKMAP_IMAGE_METADATA_MISMATCH' }
                            $inside = $true; $targetDepth = $reader.Depth
                        }
                        continue
                    }
                    if ($inside -and $reader.LocalName -ceq 'Block') { $blocks++; continue }
                    if ($inside -and $reader.LocalName -ceq 'FileHash') {
                        $fileHashes++; $bytes = [Convert]::FromBase64String($reader.GetAttribute('Hash'))
                        if ($bytes.Length -ne 32) { throw 'SOWC_BLOCKMAP_IMAGE_HASH_INVALID' }
                        $declared = [BitConverter]::ToString($bytes).Replace('-', '')
                    }
                } elseif ($inside -and $reader.NodeType -eq [Xml.XmlNodeType]::EndElement -and
                    $reader.Depth -eq $targetDepth -and $reader.LocalName -ceq 'File') { $inside = $false }
            }
            if (-not $rootSeen -or $targetCount -ne 1 -or $blocks -ne [int]$Profile.block_count -or
                $fileHashes -ne 1 -or [string]$declared -cne [string]$Profile.image_sha256) { throw 'SOWC_BLOCKMAP_IMAGE_RECORD_MISMATCH' }
        } finally { if ($null -ne $reader) { $reader.Dispose() } }
    } finally { $stream.Dispose() }
}

function Get-SemanticGameShortcuts {
    param([Parameter(Mandatory = $true)][string]$Aumid)
    $needle = [Text.Encoding]::Unicode.GetBytes($Aumid)
    $header = [byte[]](0x4C,0,0,0,1,0x14,2,0,0,0,0,0,0xC0,0,0,0,0,0,0,0x46)
    $directories = @([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('CommonDesktopDirectory')) |
        Where-Object { $_ } | Sort-Object -Unique
    $matches = @()
    foreach ($directory in $directories) {
        foreach ($file in @(Get-ChildItem -LiteralPath $directory -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue)) {
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -lt 64 -or $file.Length -gt 64KB) { continue }
            $bytes = [IO.File]::ReadAllBytes($file.FullName); $validHeader = $true
            for ($i = 0; $i -lt $header.Length; $i++) { if ($bytes[$i] -ne $header[$i]) { $validHeader = $false; break } }
            if (-not $validHeader) { continue }
            $occurrences = 0
            for ($i = 0; $i -le $bytes.Length - $needle.Length; $i++) {
                $equal = $true
                for ($j = 0; $j -lt $needle.Length; $j++) { if ($bytes[$i + $j] -ne $needle[$j]) { $equal = $false; break } }
                if ($equal) { $occurrences++ }
            }
            if ($occurrences -eq 1) { $matches += $file.FullName }
        }
    }
    return @($matches)
}

function Assert-StaticPreflight {
    $selection = Select-InstalledProfile; $package = $selection.Package; $profile = $selection.Profile.Data
    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -lt [int]$profile.minimum_windows_build) { throw "SOWC_WINDOWS_BUILD_UNSUPPORTED: $build" }
    if ([string]$package.Status -cne 'Ok' -or [string]$package.PackageFamilyName -cne [string]$profile.package_family_name -or
        [string]$package.PublisherId -cne [string]$profile.publisher_id -or [string]$package.Publisher -cne [string]$profile.publisher -or
        [string]$package.Architecture -cne [string]$profile.architecture -or [string]$package.Version -cne [string]$profile.version -or
        [string]$package.SignatureKind -cne 'Store' -or [bool]$package.IsDevelopmentMode -or [bool]$package.IsFramework -or
        [bool]$package.IsResourcePackage -or [bool]$package.IsPartiallyStaged) { throw 'SOWC_PACKAGE_IDENTITY_MISMATCH' }
    Assert-PackageContentIntegrity -PackageFullName ([string]$package.PackageFullName)
    $root = Resolve-PackageContentRoot -Package $package
    $manifest = Join-Path $root 'AppxManifest.xml'; $blockMap = Join-Path $root 'AppxBlockMap.xml'; $signature = Join-Path $root 'AppxSignature.p7x'
    foreach ($file in @($manifest,$blockMap,$signature)) { Assert-RegularFile -Path $file }
    if ((Get-FileHash $manifest -Algorithm SHA256).Hash -cne [string]$profile.manifest_sha256) { throw 'SOWC_MANIFEST_HASH_MISMATCH' }
    if ((Get-FileHash $blockMap -Algorithm SHA256).Hash -cne [string]$profile.block_map_sha256) { throw 'SOWC_BLOCKMAP_HASH_MISMATCH' }
    if ((Get-FileHash $signature -Algorithm SHA256).Hash -cne [string]$profile.package_signature_sha256) { throw 'SOWC_PACKAGE_SIGNATURE_HASH_MISMATCH' }
    $signatureState = Get-AuthenticodeSignature -LiteralPath $signature
    if ([string]$signatureState.Status -cne 'Valid' -or $null -eq $signatureState.SignerCertificate -or
        [string]$signatureState.SignerCertificate.Thumbprint -cne [string]$profile.signer_thumbprint) { throw 'SOWC_PACKAGE_SIGNATURE_INVALID' }
    Assert-ManifestIdentity -Path $manifest -Profile $profile; Assert-BlockMapImageRecord -Path $blockMap -Profile $profile
    $game = Join-Path $root ([string]$profile.relative_image_path); Assert-RegularFile -Path $game; $gameItem = Get-Item $game -Force
    if ([uint64]$gameItem.Length -ne [uint64]$profile.image_size -or (($gameItem.Attributes -band [IO.FileAttributes]::Encrypted) -eq 0)) { throw 'SOWC_GAME_IMAGE_METADATA_MISMATCH' }
    if (@(Get-Process -Name 'ShadowOfWar' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'SOWC_TITLE_ALREADY_RUNNING' }
    Assert-RegularFile -Path $script:GatePath
    if ((Get-FileHash $script:GatePath -Algorithm SHA256).Hash -cne $script:ExpectedGateSha256) { throw 'SOWC_GATE_INTEGRITY_FAILED' }
    $links = @(Get-SemanticGameShortcuts -Aumid ([string]$profile.aumid))
    if ($links.Count -ne 1) { throw "SOWC_GAME_SHORTCUT_AMBIGUOUS_OR_MISSING: found $($links.Count); create exactly one desktop shortcut from the Xbox app" }
    return [pscustomobject]@{ Profile=$profile; Package=$package; ContentRoot=$root; ShortcutCount=$links.Count }
}

function Assert-XboxPrerequisites {
    foreach ($name in @('GamingServices','GamingServicesNet')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ([string]$service.Status -cne 'Running') { throw "SOWC_SERVICE_NOT_RUNNING: $name" }
    }
    foreach ($name in @('XblAuthManager','XblGameSave')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ([string]$service.StartType -ceq 'Disabled') { throw "SOWC_SERVICE_DISABLED: $name" }
    }
    if (-not [Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()) { throw 'SOWC_NETWORK_UNAVAILABLE' }
}

function Get-SafeWgsSnapshot {
    param([string]$Root = $script:WgsRoot)
    if (-not (Test-Path -LiteralPath $Root)) { return [ordered]@{RootExists=$false;Directories=@();Files=[ordered]@{};TotalBytes=[uint64]0} }
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not $rootItem.PSIsContainer -or (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'SOWC_WGS_ROOT_INVALID' }
    $canonical = [IO.Path]::GetFullPath($Root).TrimEnd('\'); $directories = New-Object 'Collections.Generic.List[string]'
    $files = [ordered]@{}; $stack = New-Object 'Collections.Generic.Stack[string]'; $stack.Push($canonical); [uint64]$total = 0
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'SOWC_WGS_REPARSE_REJECTED' }
            $relative = $item.FullName.Substring($canonical.Length).TrimStart('\')
            if ($item.PSIsContainer) { $directories.Add($relative); $stack.Push($item.FullName) }
            else {
                [uint64]$length = $item.Length; $total += $length
                if ($files.Count -ge 10000 -or $total -gt 4GB) { throw 'SOWC_WGS_SAFETY_LIMIT_EXCEEDED' }
                $files[$relative] = "${length}|$((Get-FileHash $item.FullName -Algorithm SHA256).Hash)"
            }
        }
    }
    return [ordered]@{RootExists=$true;Directories=@($directories | Sort-Object);Files=$files;TotalBytes=$total}
}

function Test-SameSnapshot {
    param($Before,$After)
    if ([bool]$Before.RootExists -ne [bool]$After.RootExists -or [uint64]$Before.TotalBytes -ne [uint64]$After.TotalBytes) { return $false }
    $bd=@($Before.Directories|Sort-Object); $ad=@($After.Directories|Sort-Object); if ($bd.Count -ne $ad.Count) { return $false }
    for($i=0;$i -lt $bd.Count;$i++){if($bd[$i]-cne$ad[$i]){return $false}}
    $bk=@($Before.Files.Keys|Sort-Object); $ak=@($After.Files.Keys|Sort-Object); if($bk.Count-ne$ak.Count){return $false}
    for($i=0;$i-lt$bk.Count;$i++){if($bk[$i]-cne$ak[$i]-or[string]$Before.Files[$bk[$i]]-cne[string]$After.Files[$ak[$i]]){return $false}}
    return $true
}

function Wait-StableWgsSnapshot {
    param([int]$TimeoutSeconds=180,[int]$StableSeconds=30,[int]$PollSeconds=2)
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds);$prior=$null;$stableSince=$null
    do {
        try {
            $current=Get-SafeWgsSnapshot
            if($null-ne$prior-and(Test-SameSnapshot $prior $current)){
                if($null-eq$stableSince){$stableSince=[DateTime]::UtcNow}
                if(([DateTime]::UtcNow-$stableSince).TotalSeconds-ge$StableSeconds){return $current}
            } else {$stableSince=$null}
            $prior=$current
        } catch {$prior=$null;$stableSince=$null}
        Start-Sleep -Seconds $PollSeconds
    } while([DateTime]::UtcNow-lt$deadline)
    throw 'SOWC_WGS_SETTLE_TIMEOUT'
}

function New-VerifiedWgsBackup {
    param([ValidateSet('pre-run','post-run')][string]$Kind,$ExpectedSnapshot)
    Initialize-PrivateRoot
    if(-not(Test-Path -LiteralPath $script:BackupRoot -PathType Container)){[void](New-Item -ItemType Directory -Path $script:BackupRoot);Set-PrivateDirectoryAcl $script:BackupRoot}
    $name='{0}-{1}-{2}'-f$Kind,[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'),[Guid]::NewGuid().ToString('N').Substring(0,8)
    $final=Join-Path $script:BackupRoot $name;$partial="$final.partial";[void](New-Item -ItemType Directory -Path $partial);Set-PrivateDirectoryAcl $partial
    if($ExpectedSnapshot.RootExists){
        $copyRoot=Join-Path $partial 'wgs';[void](New-Item -ItemType Directory -Path $copyRoot)
        foreach($relative in @($ExpectedSnapshot.Directories|Sort-Object)){[void][IO.Directory]::CreateDirectory((Join-Path $copyRoot $relative))}
        foreach($relative in @($ExpectedSnapshot.Files.Keys|Sort-Object)){
            $destination=Join-Path $copyRoot $relative;[void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
            [IO.File]::Copy((Join-Path $script:WgsRoot $relative),$destination,$false)
        }
        $copied=Get-SafeWgsSnapshot -Root $copyRoot;if(-not(Test-SameSnapshot $ExpectedSnapshot $copied)){throw 'SOWC_BACKUP_COPY_MISMATCH'}
    }
    $sourceAfter=Get-SafeWgsSnapshot;if(-not(Test-SameSnapshot $ExpectedSnapshot $sourceAfter)){throw 'SOWC_WGS_CHANGED_DURING_BACKUP'}
    $manifest=New-Object 'Collections.Generic.List[string]';$manifest.Add('magic=SOW_COMPAT_WGS_BACKUP_V1');$manifest.Add("kind=$Kind")
    $manifest.Add('captured_utc='+[DateTime]::UtcNow.ToString('o'));$manifest.Add("root_existed=$([bool]$ExpectedSnapshot.RootExists)");$manifest.Add("total_bytes=$($ExpectedSnapshot.TotalBytes)")
    foreach($d in @($ExpectedSnapshot.Directories|Sort-Object)){$manifest.Add("directory=$d")};foreach($f in @($ExpectedSnapshot.Files.Keys|Sort-Object)){$manifest.Add("file=$f|$($ExpectedSnapshot.Files[$f])")}
    [IO.File]::WriteAllLines((Join-Path $partial 'MANIFEST.txt'),$manifest,(New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $partial -Destination $final;Assert-PrivateDirectoryAcl $final;return $final
}

function Copy-BackupToExternal {
    param([string]$BackupPath,[string]$Root)
    if([string]::IsNullOrWhiteSpace($Root)){return $null};$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\');$item=Get-Item -LiteralPath $rootPath -Force
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'SOWC_EXTERNAL_BACKUP_ROOT_INVALID' }
    $destination=Join-Path $rootPath (Split-Path -Leaf $BackupPath);if(Test-Path -LiteralPath $destination){throw 'SOWC_EXTERNAL_BACKUP_COLLISION'}
    Copy-Item -LiteralPath $BackupPath -Destination $destination -Recurse;return $destination
}

function Assert-NoUnresolvedRun {
    if(-not(Test-Path -LiteralPath $script:BaseRoot)){return};Assert-PrivateDirectoryAcl $script:BaseRoot
    $journal=Join-Path $script:BaseRoot 'active.journal';if(Test-Path -LiteralPath $journal){throw "SOWC_RECOVERY_REQUIRED: $journal"}
}

function New-StagedGate {
    Initialize-PrivateRoot;Assert-RegularFile $script:GatePath
    if((Get-FileHash $script:GatePath -Algorithm SHA256).Hash-cne$script:ExpectedGateSha256){throw 'SOWC_GATE_INTEGRITY_FAILED'}
    do{$run=Join-Path $script:BaseRoot ('r-'+[Guid]::NewGuid().ToString('N').Substring(0,16))}while(Test-Path -LiteralPath $run)
    [void](New-Item -ItemType Directory -Path $run);Set-PrivateDirectoryAcl $run;$staged=Join-Path $run 'g.exe';[IO.File]::Copy($script:GatePath,$staged,$false)
    if((Get-FileHash $staged -Algorithm SHA256).Hash-cne$script:ExpectedGateSha256){throw 'SOWC_STAGED_GATE_MISMATCH'};return $staged
}

function Invoke-Gate {
    param([string]$Path,[string[]]$Arguments)
    Push-Location (Split-Path -Parent $Path);$old=$ErrorActionPreference;$ErrorActionPreference='Continue'
    try { & $Path @Arguments 2>&1 | ForEach-Object { Write-Host $_.ToString() }; return [int]$LASTEXITCODE } finally { $ErrorActionPreference=$old; Pop-Location }
}

function Invoke-Recovery {
    Initialize-PrivateRoot;$journal=Join-Path $script:BaseRoot 'active.journal';Assert-RegularFile $journal;$fields=[ordered]@{}
    foreach($line in [IO.File]::ReadAllLines($journal,[Text.Encoding]::UTF8)){$split=$line.IndexOf('=');if($split-le0){throw 'SOWC_RECOVERY_JOURNAL_MALFORMED'};$key=$line.Substring(0,$split);if($fields.Contains($key)){throw 'SOWC_RECOVERY_JOURNAL_DUPLICATE_KEY'};$fields[$key]=$line.Substring($split+1)}
    $selection=Select-InstalledProfile;if([string]$fields.magic-cne'SOW_PACKAGE_GATE_JOURNAL_V1'-or[string]$fields.package-cne[string]$selection.Profile.Data.package_full_name){throw 'SOWC_RECOVERY_JOURNAL_IDENTITY_MISMATCH'}
    $resultPath=[IO.Path]::GetFullPath([string]$fields.result_utf8);$run=Split-Path -Parent $resultPath
    if ((Split-Path -Parent $run) -cne $script:BaseRoot -or (Split-Path -Leaf $run) -cnotmatch '^r-[0-9a-f]{16}$') { throw 'SOWC_RECOVERY_RUN_PATH_INVALID' }
    Assert-PrivateDirectoryAcl $run;$staged=Join-Path $run 'g.exe';Assert-RegularFile $staged
    if((Get-FileHash $staged -Algorithm SHA256).Hash-cne$script:ExpectedGateSha256){throw 'SOWC_RECOVERY_GATE_MISMATCH'}
    $attempt=[Guid]::NewGuid().ToString('N');$receipt=Join-Path $run "recovery-$attempt.receipt";$exit=Invoke-Gate $staged @('--recover-debug','--receipt',$attempt,$receipt)
    if ($exit -ne 0) { throw "SOWC_RECOVERY_FAILED: $exit" }; Write-Host 'RECOVERY_OK' -ForegroundColor Green
}

function ConvertTo-SafeSupportText {
    param([AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    $safe = $Text.Replace("`0", '')
    $knownValues = @(
        @([Environment]::GetFolderPath('UserProfile'), '%USERPROFILE%'),
        @([Environment]::GetFolderPath('LocalApplicationData'), '%LOCALAPPDATA%'),
        @([Environment]::GetFolderPath('Desktop'), '%DESKTOP%'),
        @($PSScriptRoot, '<APP_ROOT>'),
        @([Environment]::UserName, '<USER>'),
        @([Environment]::MachineName, '<COMPUTER>')
    )
    foreach ($entry in $knownValues) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry[0])) {
            $safe = [regex]::Replace($safe, [regex]::Escape([string]$entry[0]),
                [string]$entry[1], [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $safe = [regex]::Replace($safe, '(?im)^.*\b(?:authorization|bearer|token|password|secret|cookie)\b.*$', '<REDACTED_SENSITIVE_LINE>')
    $safe = [regex]::Replace($safe, '(?i)\b[A-Z]:\\[^\r\n"''<>|]*', '<PATH>')
    $safe = [regex]::Replace($safe, '(?m)\\\\[^\r\n"''<>|]*', '<UNC_PATH>')
    $safe = [regex]::Replace($safe, '\bS-\d-\d+(?:-\d+){1,}\b', '<SID>')
    $safe = [regex]::Replace($safe, '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '<EMAIL>')
    $safe = [regex]::Replace($safe, '\b(?:\d{1,3}\.){3}\d{1,3}\b', '<IP_ADDRESS>')
    $safe = [regex]::Replace($safe, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<GUID>')
    $safe = [regex]::Replace($safe, '(?i)\b[0-9a-f]{32,128}\b', '<REDACTED_HEX>')
    $safe = [regex]::Replace($safe, '\b\d{10,20}\b', '<ACCOUNT_ID>')
    $safe = [regex]::Replace($safe, '[^\u0009\u000A\u000D\u0020-\u007E]', '?')
    if ($safe.Length -gt 65536) {
        $safe = "[Earlier output omitted; final 65536 characters retained.]`r`n" +
            $safe.Substring($safe.Length - 65536)
    }
    return $safe.Trim()
}

function Get-SafeWindowsBuildInfo {
    $version = [Environment]::OSVersion.Version
    try {
        $current = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $buildProperty = $current.PSObject.Properties['CurrentBuildNumber']
        if ($null -eq $buildProperty) { throw 'CurrentBuildNumber unavailable' }
        $build = [int]$buildProperty.Value
        $ubrProperty = $current.PSObject.Properties['UBR']
        $displayProperty = $current.PSObject.Properties['DisplayVersion']
        $editionProperty = $current.PSObject.Properties['EditionID']
        $typeProperty = $current.PSObject.Properties['InstallationType']
        $ubr = if ($null -eq $ubrProperty) { 0 } else { [int]$ubrProperty.Value }
        return [ordered]@{
            full_build = '{0}.{1}.{2}.{3}' -f $version.Major, $version.Minor, $build, $ubr
            build_number = $build
            update_build_revision = $ubr
            display_version = if ($null -eq $displayProperty) { $null } else { [string]$displayProperty.Value }
            edition_id = if ($null -eq $editionProperty) { $null } else { [string]$editionProperty.Value }
            installation_type = if ($null -eq $typeProperty) { $null } else { [string]$typeProperty.Value }
        }
    } catch {
        return [ordered]@{
            full_build = $version.ToString()
            build_number = $version.Build
            update_build_revision = $version.Revision
            display_version = $null
            edition_id = $null
            installation_type = $null
        }
    }
}

function Get-SafePackageVolumeSummary {
    param($PowerShellPackage)
    $summary = [ordered]@{ matched = $false; is_offline = $null; is_system_volume = $null }
    if ($null -eq $PowerShellPackage -or [string]::IsNullOrWhiteSpace([string]$PowerShellPackage.InstallLocation)) {
        return $summary
    }
    try {
        $install = [IO.Path]::GetFullPath([string]$PowerShellPackage.InstallLocation).TrimEnd('\') + '\'
        foreach ($volume in @(Get-AppxVolume -ErrorAction Stop)) {
            if ([string]::IsNullOrWhiteSpace([string]$volume.PackageStorePath)) { continue }
            $store = [IO.Path]::GetFullPath([string]$volume.PackageStorePath).TrimEnd('\') + '\'
            if ($install.StartsWith($store, [StringComparison]::OrdinalIgnoreCase)) {
                $summary.matched = $true
                $summary.is_offline = [bool]$volume.IsOffline
                $summary.is_system_volume = [bool]$volume.IsSystemVolume
                break
            }
        }
    } catch {
        $summary.matched = $false
    }
    return $summary
}

function Get-SafePackageDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$PackageFullName,
        $PowerShellPackage
    )
    $result = [ordered]@{
        current_user_registered = $false
        powershell_status = if ($null -eq $PowerShellPackage) { $null } else { [string]$PowerShellPackage.Status }
        signature_kind = if ($null -eq $PowerShellPackage) { $null } else { [string]$PowerShellPackage.SignatureKind }
        is_development_mode = if ($null -eq $PowerShellPackage) { $null } else { [bool]$PowerShellPackage.IsDevelopmentMode }
        is_partially_staged = if ($null -eq $PowerShellPackage) { $null } else { [bool]$PowerShellPackage.IsPartiallyStaged }
        volume = Get-SafePackageVolumeSummary -PowerShellPackage $PowerShellPackage
        initial_status = $null
        content_integrity_ok = $null
        refreshed_status = $null
        dependencies = @()
        diagnostic_error = $null
    }
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $managerType = [Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]
        $manager = $managerType::new()
        $installed = $manager.FindPackageForUser([string]::Empty, $PackageFullName)
        if ($null -eq $installed) { return $result }
        $result.current_user_registered = $true
        $result.initial_status = Get-PackageStatusSummary -Status $installed.Status
        try {
            $result.content_integrity_ok = Invoke-WinRtBooleanOperation -Operation $installed.VerifyContentIntegrityAsync()
        } catch {
            $result.content_integrity_ok = $null
        }
        $refreshed = $manager.FindPackageForUser([string]::Empty, $PackageFullName)
        if ($null -ne $refreshed) {
            $result.refreshed_status = Get-PackageStatusSummary -Status $refreshed.Status
        }
        $dependencies = New-Object 'Collections.Generic.List[object]'
        foreach ($dependency in @($installed.Dependencies | Sort-Object { [string]$_.Id.Name })) {
            $dependencyVersion = $dependency.Id.Version
            $dependencies.Add([ordered]@{
                name = [string]$dependency.Id.Name
                version = ('{0}.{1}.{2}.{3}' -f $dependencyVersion.Major, $dependencyVersion.Minor,
                    $dependencyVersion.Build, $dependencyVersion.Revision)
                architecture = [string]$dependency.Id.Architecture
                signature_kind = [string]$dependency.SignatureKind
                is_framework = [bool]$dependency.IsFramework
                is_optional = [bool]$dependency.IsOptional
                is_resource_package = [bool]$dependency.IsResourcePackage
                status = Get-PackageStatusSummary -Status $dependency.Status
            })
        }
        $result.dependencies = $dependencies.ToArray()
    } catch {
        $result.diagnostic_error = ConvertTo-SafeSupportText (($_.Exception.Message -split ':')[0])
    }
    return $result
}

function Get-SafeAppxEventSummary {
    param([string[]]$PackageTokens)
    $logs = @(
        'Microsoft-Windows-AppXDeploymentServer/Operational',
        'Microsoft-Windows-AppModel-Runtime/Admin',
        'Microsoft-Windows-AppxPackaging/Operational'
    )
    $result = [ordered]@{ window_hours = 24; messages_included = $false; logs = [ordered]@{} }
    $start = (Get-Date).AddHours(-24)
    $safeTokens = @($PackageTokens | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    foreach ($log in $logs) {
        $items = New-Object 'Collections.Generic.List[object]'
        $available = $true
        try {
            foreach ($event in @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -MaxEvents 250 -ErrorAction Stop)) {
                $message = [string]$event.Message
                $relevant = $false
                foreach ($token in $safeTokens) {
                    if ($message.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $relevant = $true; break }
                }
                if (-not $relevant) { continue }
                $hresults = @([regex]::Matches($message, '(?i)\b0x[0-9a-f]{8}\b') |
                    ForEach-Object { $_.Value.ToUpperInvariant() } | Sort-Object -Unique)
                $items.Add([ordered]@{
                    time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
                    event_id = [int]$event.Id
                    level = [int]$event.Level
                    provider = [string]$event.ProviderName
                    hresults = $hresults
                })
                if ($items.Count -ge 20) { break }
            }
        } catch {
            $available = $false
        }
        $result.logs[$log] = [ordered]@{ available = $available; events = $items.ToArray() }
    }
    return $result
}

function Get-SafeJournalSummary {
    $summary = [ordered]@{ present = $false; stage = $null; last_hresult = $null }
    $journalPath = Join-Path $script:BaseRoot 'active.journal'
    if (-not (Test-Path -LiteralPath $journalPath -PathType Leaf)) { return $summary }
    $summary.present = $true
    try {
        Assert-RegularFile -Path $journalPath
        $item = Get-Item -LiteralPath $journalPath -Force
        if ($item.Length -gt 32768) { throw 'journal too large' }
        foreach ($line in [IO.File]::ReadAllLines($journalPath, [Text.Encoding]::UTF8)) {
            if ($line -match '^stage=([a-z0-9_]+)$') { $summary.stage = $matches[1] }
            elseif ($line -match '^last_hr=([0-9A-Fa-f]{8})$') { $summary.last_hresult = $matches[1].ToUpperInvariant() }
        }
    } catch {
        $summary.stage = 'unreadable'
    }
    return $summary
}

function Get-SafeRunEvidenceSummary {
    $items = New-Object 'Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $script:BaseRoot -PathType Container)) { return @() }
    foreach ($directory in @(Get-ChildItem -LiteralPath $script:BaseRoot -Directory -Force |
            Where-Object { $_.Name -cmatch '^r-[0-9a-f]{16}$' -and
                (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) } |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 5)) {
        try {
            $files = @(Get-ChildItem -LiteralPath $directory.FullName -File -Force -ErrorAction Stop |
                Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 })
            $gate = @($files | Where-Object { $_.Name -ceq 'g.exe' } | Select-Object -First 1)
            $gateIntegrity = $null
            if ($gate.Count -eq 1) {
                $gateIntegrity = ((Get-FileHash -LiteralPath $gate[0].FullName -Algorithm SHA256).Hash -ceq
                    $script:ExpectedGateSha256)
            }
            $items.Add([ordered]@{
                last_write_utc = $directory.LastWriteTimeUtc.ToString('o')
                file_count = $files.Count
                result_present = (@($files | Where-Object { $_.Name -cmatch '^result-[0-9a-f]{32}\.txt$' }).Count -gt 0)
                claim_present = (@($files | Where-Object { $_.Name -cmatch '^result-[0-9a-f]{32}\.txt\.claim$' }).Count -gt 0)
                recovery_receipt_count = @($files | Where-Object { $_.Name -cmatch '^recovery-[0-9a-f]{32}\.receipt$' }).Count
                staged_gate_integrity_ok = $gateIntegrity
            })
        } catch {
            $items.Add([ordered]@{ last_write_utc = $directory.LastWriteTimeUtc.ToString('o'); unreadable = $true })
        }
    }
    return $items.ToArray()
}

function Write-SupportBundle {
    Initialize-PrivateRoot
    if (-not (Test-Path -LiteralPath $script:SupportRoot -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $script:SupportRoot)
    }
    Set-PrivateDirectoryAcl $script:SupportRoot

    $activityText = ''
    if (-not [string]::IsNullOrWhiteSpace($ActivityLogPath)) {
        $activityFullPath = [IO.Path]::GetFullPath($ActivityLogPath)
        Assert-RegularFile -Path $activityFullPath
        $activityItem = Get-Item -LiteralPath $activityFullPath -Force
        if ($activityItem.Length -gt 1MB) { throw 'SOWC_SUPPORT_ACTIVITY_LOG_TOO_LARGE' }
        $activityText = ConvertTo-SafeSupportText ([IO.File]::ReadAllText($activityFullPath, [Text.Encoding]::UTF8))
    }

    $profileId = $null
    $packageVersion = $null
    $wgs = $null
    $detectionError = $null
    $packageDiagnostics = $null
    $packageTokens = @()
    try {
        $selection = Select-InstalledProfile
        $profileId = [string]$selection.Profile.Data.id
        $packageVersion = [string]$selection.Package.Version
        $packageTokens = @(
            [string]$selection.Profile.Data.package_name,
            [string]$selection.Profile.Data.package_family_name,
            [string]$selection.Profile.Data.package_full_name,
            'WB-Kraken',
            'ShadowOfWar'
        )
        $packageDiagnostics = Get-SafePackageDiagnostics -PackageFullName ([string]$selection.Package.PackageFullName) `
            -PowerShellPackage $selection.Package
        $wgs = Get-SafeWgsSnapshot
    } catch {
        $detectionError = ConvertTo-SafeSupportText (($_.Exception.Message -split ':')[0])
    }

    $services = [ordered]@{}
    foreach ($name in @('GamingServices', 'GamingServicesNet', 'XblAuthManager', 'XblGameSave')) {
        try {
            $service = Get-Service $name
            $services[$name] = [ordered]@{ status = [string]$service.Status; start_type = [string]$service.StartType }
        } catch {
            $services[$name] = [ordered]@{ status = 'Unavailable'; start_type = $null }
        }
    }

    $errorCodes = @()
    if (-not [string]::IsNullOrWhiteSpace($activityText)) {
        $errorCodes = @([regex]::Matches($activityText, '\b(?:SOWC|GATE)_[A-Z0-9_]+\b') |
            ForEach-Object { $_.Value } | Sort-Object -Unique)
    }
    $journal = Get-SafeJournalSummary
    $runEvidence = @(Get-SafeRunEvidenceSummary)
    $windows = Get-SafeWindowsBuildInfo
    $appxEvents = Get-SafeAppxEventSummary -PackageTokens $packageTokens
    $bundleId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $generated = [DateTime]::UtcNow
    $data = [ordered]@{
        schema = 3
        bundle_id = $bundleId
        tool_version = $script:ToolVersion
        generated_utc = $generated.ToString('o')
        windows_build = [string]$windows.full_build
        windows = $windows
        os_64_bit = [Environment]::Is64BitOperatingSystem
        process_64_bit = [Environment]::Is64BitProcess
        powershell_version = $PSVersionTable.PSVersion.ToString()
        elevated = Test-IsElevatedAdministrator
        profile_id = $profileId
        package_version = $packageVersion
        package_process_running = (@(Get-Process ShadowOfWar -ErrorAction SilentlyContinue).Count -gt 0)
        package_diagnostics = $packageDiagnostics
        appx_events = $appxEvents
        network_available = [Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()
        services = $services
        journal = $journal
        recent_run_evidence = $runEvidence
        wgs_root_exists = if ($null -eq $wgs) { $null } else { [bool]$wgs.RootExists }
        wgs_file_count = if ($null -eq $wgs) { $null } else { [int]$wgs.Files.Count }
        wgs_total_bytes = if ($null -eq $wgs) { $null } else { [uint64]$wgs.TotalBytes }
        detection_error = $detectionError
        activity_log_included = (-not [string]::IsNullOrWhiteSpace($activityText))
        detected_error_codes = $errorCodes
        privacy = 'No event messages, paths, user or computer names, account identifiers, tokens, IP addresses, save names, save hashes, or save contents are included.'
    }

    $stage = Join-Path $script:SupportRoot ('.stage-' + [Guid]::NewGuid().ToString('N'))
    $zipName = 'SowCompat-support-{0}Z-{1}.zip' -f $generated.ToString('yyyyMMdd-HHmmss'), $bundleId
    $zipPath = Join-Path $script:SupportRoot $zipName
    $partialZip = $zipPath + '.partial'
    [void](New-Item -ItemType Directory -Path $stage)
    Set-PrivateDirectoryAcl $stage
    try {
        $utf8 = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText((Join-Path $stage 'support-report.json'),
            ($data | ConvertTo-Json -Depth 8), $utf8)
        if (-not [string]::IsNullOrWhiteSpace($activityText)) {
            [IO.File]::WriteAllText((Join-Path $stage 'activity-log.txt'), $activityText + "`r`n", $utf8)
        }
        $instructions = @'
SowCompat support bundle
========================

1. You may inspect every file in this ZIP before sharing it.
2. Open https://github.com/drnkPirate/sow-compat/issues/new?template=bug_report.yml
3. Describe what happened and drag this ZIP into the issue.
4. Never attach Xbox save files, WGS folders, screenshots containing account data,
   authentication tokens, or files from WindowsApps.

Nothing was uploaded automatically. This bundle intentionally excludes paths,
user and computer names, account identifiers, tokens, IP addresses, save names,
save hashes, and save contents.
'@
        [IO.File]::WriteAllText((Join-Path $stage 'HOW-TO-SHARE.txt'), $instructions.Trim() + "`r`n", $utf8)
        $manifest = New-Object 'Collections.Generic.List[string]'
        foreach ($file in @(Get-ChildItem -LiteralPath $stage -File | Sort-Object Name)) {
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $manifest.Add("$hash  $($file.Name)")
        }
        [IO.File]::WriteAllLines((Join-Path $stage 'BUNDLE-SHA256SUMS.txt'), $manifest, $utf8)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($stage, $partialZip,
            [IO.Compression.CompressionLevel]::Optimal, $false)
        Move-Item -LiteralPath $partialZip -Destination $zipPath
    } finally {
        if (Test-Path -LiteralPath $partialZip -PathType Leaf) { Remove-Item -LiteralPath $partialZip -Force }
        if (Test-Path -LiteralPath $stage -PathType Container) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
    Write-Host "SUPPORT_BUNDLE_OK: $zipPath" -ForegroundColor Green
    Write-Host 'Nothing was uploaded. Review the ZIP, then attach it to a GitHub bug report.'
}

function Invoke-Install {
    if(Test-IsElevatedAdministrator){throw 'SOWC_INSTALL_MUST_RUN_AS_STANDARD_USER'};Initialize-PrivateRoot;$app=Join-Path $script:BaseRoot 'app'
    if(-not(Test-Path -LiteralPath $app)){[void](New-Item -ItemType Directory -Path $app)};Set-PrivateDirectoryAcl $app
    $gui=Join-Path $PSScriptRoot 'SowCompat.exe';Assert-RegularFile $gui
    $sourceRoot=[IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\');$destinationRoot=[IO.Path]::GetFullPath($app).TrimEnd('\')
    if(-not $sourceRoot.Equals($destinationRoot,[StringComparison]::OrdinalIgnoreCase)){
        foreach($name in @('SowCompat.exe','g.exe','sow_compat.ps1','README.md','USER-GUIDE.md','SUPPORT.md','LICENSE','SECURITY.md','THREAT-MODEL.md')){$source=Join-Path $PSScriptRoot $name;if(Test-Path -LiteralPath $source -PathType Leaf){Copy-Item -LiteralPath $source -Destination (Join-Path $app $name) -Force}}
        $destinationProfiles=Join-Path $app 'profiles';if(-not(Test-Path -LiteralPath $destinationProfiles)){[void](New-Item -ItemType Directory -Path $destinationProfiles)}
        Copy-Item -Path (Join-Path $script:ProfilesRoot '*.json') -Destination $destinationProfiles -Force
    }
    $shell=New-Object -ComObject WScript.Shell;$desktop=[Environment]::GetFolderPath('Desktop');$shortcutPath=Join-Path $desktop 'Shadow of War Compatibility.lnk';$shortcut=$shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath=Join-Path $app 'SowCompat.exe';$shortcut.Arguments='';$shortcut.WorkingDirectory=$app;$shortcut.Description='Shadow of War Compatibility (Microsoft Store/Xbox app)';$shortcut.Save()
    Write-Host "INSTALL_OK: $app" -ForegroundColor Green;Write-Host "Launcher: $shortcutPath"
}

function Invoke-Uninstall {
    if(Test-Path -LiteralPath (Join-Path $script:BaseRoot 'active.journal')){throw 'SOWC_RECOVERY_REQUIRED_BEFORE_UNINSTALL'};$app=Join-Path $script:BaseRoot 'app';$shortcut=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Shadow of War Compatibility.lnk'
    if(Test-Path -LiteralPath $shortcut){Remove-Item -LiteralPath $shortcut -Force};if(Test-Path -LiteralPath $app){Remove-Item -LiteralPath $app -Recurse -Force}
    Write-Host 'UNINSTALL_OK: app and launcher removed; backups, support bundles, and run evidence preserved.' -ForegroundColor Green
}

function Invoke-SelfTest {
    Assert-RegularFile $script:GatePath;if((Get-FileHash $script:GatePath -Algorithm SHA256).Hash-cne$script:ExpectedGateSha256){throw 'SOWC_SELFTEST_GATE_HASH'}
    $profiles=@(Get-TrustedProfiles); if ($profiles.Count -ne $script:TrustedProfileHashes.Count) { throw 'SOWC_SELFTEST_PROFILE_COUNT' }; $native=Invoke-Gate $script:GatePath @('--self-test'); if ($native -ne 0) { throw "SOWC_SELFTEST_NATIVE: $native" }
    $fixture=Join-Path ([IO.Path]::GetTempPath()) ('sowcompat-test-'+[Guid]::NewGuid().ToString('N'))
    try{
        [void](New-Item -ItemType Directory -Path $fixture); $empty=Get-SafeWgsSnapshot -Root $fixture; if (-not $empty.RootExists -or $empty.Files.Count -ne 0) { throw 'SOWC_SELFTEST_EMPTY_WGS' }
        $nested=Join-Path $fixture 'profile unicode 测试\container-a';[void][IO.Directory]::CreateDirectory($nested);[IO.File]::WriteAllBytes((Join-Path $nested 'payload'),[byte[]](0,1,2,3,255))
        $one=Get-SafeWgsSnapshot -Root $fixture;$two=Get-SafeWgsSnapshot -Root $fixture;if(-not(Test-SameSnapshot $one $two)){throw 'SOWC_SELFTEST_SNAPSHOT_STABILITY'}
        [IO.File]::WriteAllBytes((Join-Path $nested 'payload'),[byte[]](0,1,2,4,255));$changed=Get-SafeWgsSnapshot -Root $fixture;if(Test-SameSnapshot $one $changed){throw 'SOWC_SELFTEST_MUTATION_NOT_DETECTED'}
        $profileText=[IO.File]::ReadAllText($profiles[0].Path,[Text.Encoding]::UTF8)+' ';$sha=[Security.Cryptography.SHA256]::Create();try{$tampered=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($profileText))).Replace('-','')}finally{$sha.Dispose()};if($tampered-ceq$profiles[0].Hash){throw 'SOWC_SELFTEST_PROFILE_TAMPER'}
    }finally{if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}}
    $redactionFixture="SOWC_TEST_FAILURE C:\Users\Private\file.txt`nuser@example.com`nS-1-5-21-111-222-333-1001`n1234567890123456`n192.168.1.9`n0123456789abcdef0123456789abcdef"
    $redacted=ConvertTo-SafeSupportText $redactionFixture
    foreach($secret in @('C:\Users\Private','user@example.com','S-1-5-21-111-222-333-1001','1234567890123456','192.168.1.9','0123456789abcdef0123456789abcdef')){if($redacted.Contains($secret)){throw 'SOWC_SELFTEST_SUPPORT_REDACTION_LEAK'}}
    foreach($expected in @('SOWC_TEST_FAILURE','<PATH>','<EMAIL>','<SID>','<ACCOUNT_ID>','<IP_ADDRESS>','<REDACTED_HEX>')){if(-not$redacted.Contains($expected)){throw "SOWC_SELFTEST_SUPPORT_REDACTION_MISSING: $expected"}}
    $statusFixture=[ordered]@{verify_is_ok=$false;data_offline=$false;dependency_issue=$true;deployment_in_progress=$false;disabled=$false;is_partially_staged=$false;license_issue=$false;modified=$false;needs_remediation=$false;not_available=$false;package_offline=$false;servicing=$false;tampered=$true}
    $statusFailures=@(Get-PackageStatusFailureNames -Summary $statusFixture)
    if ($statusFailures.Count -ne 2 -or $statusFailures[0] -cne 'dependency_issue' -or
        $statusFailures[1] -cne 'tampered') { throw 'SOWC_SELFTEST_PACKAGE_STATUS_SUMMARY' }
    Write-Host 'SELFTEST_OK: native, profile-integrity, WGS mutation, and support-redaction tests passed; no package or live WGS changed.' -ForegroundColor Green
}

if($Install){Invoke-Install;exit 0};if($Uninstall){Invoke-Uninstall;exit 0};if($SelfTest){Invoke-SelfTest;exit 0};if($ExportSupportBundle){Write-SupportBundle;exit 0}
if(Test-IsElevatedAdministrator){throw 'SOWC_ELEVATED_PROCESS_REJECTED: run at normal user integrity'};if($Recover){Invoke-Recovery;exit 0}
$context=Assert-StaticPreflight;Assert-XboxPrerequisites;Assert-NoUnresolvedRun
Write-Host "CHECK_OK: profile=$($context.Profile.id); package=$($context.Package.PackageFullName)" -ForegroundColor Green
Write-Host 'No network, firewall, service, registry, package, WindowsApps ACL, or save data was changed.'
if (-not $Play -and -not $PrepareOnly) { exit 0 }
$before=Wait-StableWgsSnapshot -TimeoutSeconds 60 -StableSeconds 6 -PollSeconds 2;$preBackup=New-VerifiedWgsBackup -Kind 'pre-run' -ExpectedSnapshot $before;$externalPre=Copy-BackupToExternal -BackupPath $preBackup -Root $ExternalBackupRoot
Write-Host "PRE_RUN_BACKUP_OK: $preBackup" -ForegroundColor Green;if($externalPre){Write-Host "EXTERNAL_PRE_RUN_BACKUP_OK: $externalPre"};if($PrepareOnly){Write-Host 'PREPARE_ONLY_OK: package debugging was not enabled and the game was not started.' -ForegroundColor Green;exit 0}
$staged=New-StagedGate;$run=Split-Path -Parent $staged;Write-Host 'ARMING: the Xbox app will open. Click Play once, then play and save normally.' -ForegroundColor Cyan
$controllerExit=255;$postFailure=$null;$postBackup=$null
try{$controllerExit=Invoke-Gate $staged @('--arm-online-play')}finally{
    try{Write-Host 'CLOUD_SETTLE_WAIT: waiting for 30 uninterrupted seconds of identical local WGS snapshots.' -ForegroundColor Cyan;$after=Wait-StableWgsSnapshot -TimeoutSeconds 180 -StableSeconds 30 -PollSeconds 2;$postBackup=New-VerifiedWgsBackup -Kind 'post-run' -ExpectedSnapshot $after;$externalPost=Copy-BackupToExternal -BackupPath $postBackup -Root $ExternalBackupRoot;Write-Host "POST_RUN_BACKUP_OK: $postBackup" -ForegroundColor Green;if($externalPost){Write-Host "EXTERNAL_POST_RUN_BACKUP_OK: $externalPost"}}
    catch{$postFailure=$_.Exception.Message;Write-Host "SOWC_POST_RUN_BACKUP_FAILED: $postFailure" -ForegroundColor Red}
}
if ($controllerExit -ne 0) { throw "SOWC_NATIVE_CONTROLLER_FAILED: exit=$controllerExit; run=$run" }; if ($null -ne $postFailure) { throw "SOWC_POST_RUN_BACKUP_FAILED: $postFailure" }
Write-Host 'PLAY_SESSION_COMPLETE: title exited, debug hook and process-local patch are gone, and the stable local save was backed up.' -ForegroundColor Green
Write-Host 'This is not proof of a Microsoft cloud-server acknowledgement; verify cross-device sync separately.' -ForegroundColor Yellow
