[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(ParameterSetName = 'Play')][switch]$Play,
    [Parameter(ParameterSetName = 'Check')][switch]$CheckOnly,
    [Parameter(ParameterSetName = 'Prepare')][switch]$PrepareOnly,
    [Parameter(ParameterSetName = 'Recover')][switch]$Recover,
    [Parameter(ParameterSetName = 'SelfTest')][switch]$SelfTest,
    [Parameter(ParameterSetName = 'Support')][switch]$ExportSupportBundle,
    [Parameter(ParameterSetName = 'Install')][switch]$Install,
    [Parameter(ParameterSetName = 'Uninstall')][switch]$Uninstall,
    [Parameter(ParameterSetName = 'Play')]
    [Parameter(ParameterSetName = 'Prepare')]
    [string]$ExternalBackupRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:ToolVersion = '10.0.0-preview.1'
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

function Assert-PackageContentIntegrity {
    param([Parameter(Mandatory = $true)][string]$PackageFullName)
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $managerType = [Windows.Management.Deployment.PackageManager,Windows.Management.Deployment,ContentType=WindowsRuntime]
    $manager = $managerType::new()
    $installed = $manager.FindPackageForUser([string]::Empty, $PackageFullName)
    if ($null -eq $installed -or -not $installed.Status.VerifyIsOK()) { throw 'SOWC_PACKAGE_STATUS_NOT_OK' }
    $operation = $installed.VerifyContentIntegrityAsync()
    $asTask = @([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -ceq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Length -eq 1 -and
        $_.GetParameters().Length -eq 1 -and $_.ReturnType.IsGenericType -and
        $_.ReturnType.GetGenericTypeDefinition() -eq [Threading.Tasks.Task``1]
    })
    if ($asTask.Count -ne 1) { throw 'SOWC_WINRT_TASK_BRIDGE_AMBIGUOUS' }
    $task = $asTask[0].MakeGenericMethod([bool]).Invoke($null, @($operation))
    if (-not $task.GetAwaiter().GetResult() -or -not $installed.Status.VerifyIsOK()) {
        throw 'SOWC_PACKAGE_CONTENT_INTEGRITY_FAILED'
    }
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

function Write-SupportBundle {
    Initialize-PrivateRoot;if(-not(Test-Path -LiteralPath $script:SupportRoot)){[void](New-Item -ItemType Directory -Path $script:SupportRoot);Set-PrivateDirectoryAcl $script:SupportRoot}
    $profileId=$null;$packageVersion=$null;$wgs=$null;$errorCode=$null
    try{$selection=Select-InstalledProfile;$profileId=[string]$selection.Profile.Data.id;$packageVersion=[string]$selection.Package.Version;$wgs=Get-SafeWgsSnapshot}catch{$errorCode=($_.Exception.Message-split':')[0]}
    $services=[ordered]@{};foreach($name in @('GamingServices','GamingServicesNet','XblAuthManager','XblGameSave')){try{$s=Get-Service $name;$services[$name]="Status=$($s.Status);StartType=$($s.StartType)"}catch{$services[$name]='Unavailable'}}
    $data=[ordered]@{schema=1;tool_version=$script:ToolVersion;generated_utc=[DateTime]::UtcNow.ToString('o');windows_build=[Environment]::OSVersion.Version.ToString();profile_id=$profileId;package_version=$packageVersion;package_process_running=(@(Get-Process ShadowOfWar -ErrorAction SilentlyContinue).Count-gt0);network_available=[Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable();services=$services;unresolved_journal=(Test-Path -LiteralPath (Join-Path $script:BaseRoot 'active.journal'));wgs_root_exists=if($null-eq$wgs){$null}else{[bool]$wgs.RootExists};wgs_file_count=if($null-eq$wgs){$null}else{[int]$wgs.Files.Count};wgs_total_bytes=if($null-eq$wgs){$null}else{[uint64]$wgs.TotalBytes};detection_error=$errorCode;privacy='No paths, account identifiers, tokens, save hashes, save names, or save contents included.'}
    $path=Join-Path $script:SupportRoot ('support-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.json');[IO.File]::WriteAllText($path,($data|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)));Write-Host "SUPPORT_BUNDLE_OK: $path" -ForegroundColor Green
}

function Invoke-Install {
    if(Test-IsElevatedAdministrator){throw 'SOWC_INSTALL_MUST_RUN_AS_STANDARD_USER'};Initialize-PrivateRoot;$app=Join-Path $script:BaseRoot 'app'
    if(-not(Test-Path -LiteralPath $app)){[void](New-Item -ItemType Directory -Path $app)};Set-PrivateDirectoryAcl $app
    $gui=Join-Path $PSScriptRoot 'SowCompat.exe';Assert-RegularFile $gui
    $sourceRoot=[IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\');$destinationRoot=[IO.Path]::GetFullPath($app).TrimEnd('\')
    if(-not $sourceRoot.Equals($destinationRoot,[StringComparison]::OrdinalIgnoreCase)){
        foreach($name in @('SowCompat.exe','g.exe','sow_compat.ps1','README.md','LICENSE','SECURITY.md','THREAT-MODEL.md')){$source=Join-Path $PSScriptRoot $name;if(Test-Path -LiteralPath $source -PathType Leaf){Copy-Item -LiteralPath $source -Destination (Join-Path $app $name) -Force}}
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
    Write-Host 'SELFTEST_OK: native, profile-integrity, empty/multi-tree/Unicode WGS and mutation tests passed; no package or live WGS changed.' -ForegroundColor Green
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
