# Harden System Security

Harden System Security is a modern secure lightweight application that can help you harden, secure and lock down your system. It is designed to be user-friendly and efficient, providing a range of features to enhance the security of your Windows operating system.

## How To Install or Update The App

### Use The [Microsoft Store](https://apps.microsoft.com/detail/9p7ggfl7dx57)

<a href="https://apps.microsoft.com/detail/9p7ggfl7dx57?referrer=appbadge&mode=direct">
	<img src="https://get.microsoft.com/images/en-us%20dark.svg" width="270"/>
</a>

### Use Winget

You can utilize Winget to automate the installation of the Harden System Security.

```powershell
winget install --id 9p7ggfl7dx57 --exact --accept-package-agreements --accept-source-agreements --force --source msstore
```

<br>

Please feel free to open a discussion if you have any questions about the build process, security, how to use or have feedbacks. [**Source code on this repository**](https://github.com/HotCakeX/Harden-Windows-Security/tree/main/Harden%20System%20Security)

<br>

### Supported Operation Systems

* Windows 11 24H2
* Windows 11 23H2
* Windows 11 22H2
* Windows Server 2025

<br>

## Preview of the App

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/e98e3a322d2bd04b6a77e2cd4d2d8909d0eb6af0/Pictures/Gifs/HardenWindowsSecurityApp.gif" alt="Harden System Security preview"/>

</div>

<br>

## Technical Details of The App

* Secure and transparent development and build process.
* Built using [WinUI3](https://learn.microsoft.com/windows/apps/winui/winui3/) / [XAML](https://github.com/microsoft/microsoft-ui-xaml) / [C#](https://learn.microsoft.com/dotnet/csharp/).
* Built using the latest [.NET](https://dotnet.microsoft.com) SDK.
* Powered by the [WinAppSDK](https://github.com/microsoft/WindowsAppSDK) (formerly Project Reunion).
* Packaged with the modern [MSIX](https://learn.microsoft.com/windows/msix/overview) format.
* Incorporates the [Mica](https://learn.microsoft.com/windows/apps/design/style/mica) material design for backgrounds.
* Adopts the Windows 11 [Fluent design system](https://fluent2.microsoft.design/components/windows).
* Fast execution and startup time.
* 0 required dependency.
* 0 Third-party library or file used.
* 0 Telemetry or data collection.
* 100% clean uninstallation.
* 100% open-source and free to use.
* Natively supports X64 and ARM64 architectures.
* Full [Trimming](https://learn.microsoft.com/dotnet/core/deploying/trimming/trim-self-contained) and [Native AOT](https://learn.microsoft.com/dotnet/core/deploying/native-aot) support.

<br>

## Security

Harden System Security is architected with a security-first philosophy from its inception. Every feature is designed and implemented with an offensive security mindset, ensuring that security is never an afterthought—and never will be. When selecting a solution tasked with defending critical systems, the last thing you want is a so‑called security tool that silently broadens your attack surface or neglects foundational safeguards. This application is built to be inherently trustworthy, defensible, and resilient.

### Dependencies

Harden System Security explicitly and unequivocally maintains zero third‑party dependencies. It relies solely on the .NET SDK, the Windows App SDK, and a minimal set of small trusted Microsoft platform components for the User Interface. This deliberate constraint sharply reduces the attack surface and virtually eliminates common software supply chain attack vectors. Rather than pulling transient packages to satisfy feature gaps, required capabilities are purpose‑built in-house—implemented correctly, audibly, and securely. While this increases development effort and time, the mission and deployment contexts of this application more than justify the investment.

Leveraging GitHub's native automation (including Dependabot) alongside Microsoft's patch cadence, security and platform updates can be integrated and released rapidly, preserving both stability and assurance.

### Exploit Protection

The application avoids dynamic code generation, enhancing security posture and reducing vulnerability exposure. This design ensures compatibility with advanced OS-level exploit mitigation. The Harden System Security supports [process mitigations / Exploit Protections](https://learn.microsoft.com/defender-endpoint/exploit-protection-reference) such as: `Blocking low integrity images`, `Blocking remote images`, `Blocking untrusted fonts`, `Strict Control Flow Guard`, `Disabling extension points`, `Export Address Filtering`, `Hardware enforced stack protection`, `Import Address Filtering`, `Validate handle usage`, `Validate stack integrity`.

This disciplined approach bolsters resistance against memory corruption, injection, and tampering techniques frequently leveraged by sophisticated adversaries.

### Code Review

The codebase is extensively and thoughtfully documented, enabling reviewers to trace logic, validate control flows, and assess security-relevant decisions with minimal friction. I remain fully available to clarify design rationale, threat assumptions, or implementation details whenever deeper scrutiny is desired.

<br>

## Documentation

Full documentation for every single feature of the Harden System Security app is available on [the GitHub Wiki](https://github.com/HotCakeX/Harden-Windows-Security/wiki#-harden-system-security--)

<br>

## Supported Languages

The Harden System Security fully supports the following languages.

* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/usa.svg" width="25" alt="Country flag"> English
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/israel.svg" width="25" alt="Country flag"> Hebrew
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/greece.svg" width="25" alt="Country flag"> Greek
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/india.svg" width="25" alt="Country flag"> Hindi
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/india.svg" width="25" alt="Country flag"> Malayalam
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/saudi-arabia.svg" width="25" alt="Country flag"> Arabic
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/mexico.svg" width="25" alt="Country flag"> Spanish
* <img src="https://raw.githubusercontent.com/HotCakeX/.github/ea13e9ebae5baa7343c9c1721f58cf4400cd88f6/Pictures/Country%20Flags/poland.svg" width="25" alt="Country flag"> Polish

<br>

## How To Build The Harden System Security Locally?

You can build the Harden System Security application directly from the source code locally on your device without using any 3rd party tools in a completely automated way. It will create the MSIXBundle file containing the X64 and ARM64 MSIX packages.

The build process will generate complete log files and you can use the [MSBuild Structured Log Viewer](https://learn.microsoft.com/shows/visual-studio-toolbox/msbuild-structured-log-viewer) to inspect them.

<details>

<summary>
✨ Click/Tap here to see the PowerShell code ✨
</summary>

<br>

```powershell
# Requires -Version 7.5
# Requires -RunAsAdministrator
function Build_HSS {
    param(
        [bool]$DownloadRepo,
        [bool]$InstallDeps,
        [bool]$Workflow,
        [bool]$UpdateWorkLoads,
        [bool]$Upload
    )

    $ErrorActionPreference = 'Stop'
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1 -Force

    [System.String]$script:AppControlManagerDirectory

    if ($DownloadRepo) {

        [System.String]$BranchName = 'main'
        [System.String]$RepoName = 'Harden-Windows-Security'
        [System.String]$RepoUrl = "https://github.com/HotCakeX/$RepoName/archive/refs/heads/$BranchName.zip"
        [System.String]$ZipPath = [System.IO.Path]::Combine($env:TEMP, "$RepoName.zip")
        [System.String]$InitialWorkingDirectory = $PWD.Path
        $script:AppControlManagerDirectory = [System.IO.Path]::Combine($InitialWorkingDirectory, "$RepoName-$BranchName", 'Harden System Security')

        if (Test-Path -Path $script:AppControlManagerDirectory -PathType Container) {
            Remove-Item -Path $script:AppControlManagerDirectory -Recurse -Force
        }

        Invoke-WebRequest -Uri $RepoUrl -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $InitialWorkingDirectory -Force
        Remove-Item -Path $ZipPath -Force
        Set-Location -Path $script:AppControlManagerDirectory
    }
    else {
        $script:AppControlManagerDirectory = $PWD.Path
    }

    if ($InstallDeps) {

        # Install Winget if it doesn't exist
        if (!(Get-Command -Name 'winget.exe' -ErrorAction Ignore)) {

            # Retrieve the latest Winget release information
            $WingetReleases = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases'
            $LatestRelease = $WingetReleases | Select-Object -First 1
            # Direct links to the latest Winget release assets
            [string]$WingetURL = $LatestRelease.assets.browser_download_url | Where-Object -FilterScript { $_.EndsWith('.msixbundle') } | Select-Object -First 1
            [string]$WingetLicense = $LatestRelease.assets.browser_download_url | Where-Object -FilterScript { $_.EndsWith('License1.xml') } | Select-Object -First 1
            [string]$LatestWingetReleaseDependenciesZipURL = $LatestRelease.assets.browser_download_url | Where-Object -FilterScript { $_.EndsWith('DesktopAppInstaller_Dependencies.zip') } | Select-Object -First 1
            [hashtable]$Downloads = @{
                # 'Winget.msixbundle'                 = 'https://aka.ms/getwinget' This is updated slower than the GitHub release
                'DesktopAppInstaller_Dependencies.zip' = $LatestWingetReleaseDependenciesZipURL
                'Winget.msixbundle'                    = $WingetURL
                'License1.xml'                         = $WingetLicense
            }
            $Downloads.GetEnumerator() | ForEach-Object -Parallel {
                Invoke-RestMethod -Uri $_.Value -OutFile $_.Key
            }

            Expand-Archive -Path 'DesktopAppInstaller_Dependencies.zip' -DestinationPath .\ -Force

            # Required to update the Winget
            Stop-Process -Name 'WindowsTerminal' -Force -ErrorAction Ignore

            # Get the paths to all of the dependencies
            [string[]]$DependencyPaths = (Get-ChildItem -Path .\x64 -Filter '*.appx' -File -Force).FullName
            Add-AppxProvisionedPackage -Online -PackagePath 'Winget.msixbundle' -DependencyPackagePath $DependencyPaths -LicensePath 'License1.xml'

            Add-AppPackage -Path 'Winget.msixbundle' -DependencyPath "$($DependencyPaths[0])", "$($DependencyPaths[1])" -ForceTargetApplicationShutdown -ForceUpdateFromAnyVersion

        }

        Write-Host -Object 'The version of the Winget currently in use:'
        Write-Host -Object (winget --version)

        winget source update

        Write-Host -Object "`nInstalling Rust toolchain" -ForegroundColor Magenta
        $null = winget install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed to install the Rust toolchain: $LASTEXITCODE") }

        Write-Host -Object "`nInstalling .NET SDK" -ForegroundColor Magenta
        $null = winget install --id Microsoft.DotNet.SDK.Preview --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed to install .NET SDK: $LASTEXITCODE") }

        Write-Host -Object "`nInstalling Visual Studio Build Tools" -ForegroundColor Magenta
        # Downloads the online installer and automatically runs it and installs the build tools
        # https://learn.microsoft.com/windows/apps/windows-app-sdk/set-up-your-development-environment
        # https://learn.microsoft.com/visualstudio/install/workload-component-id-vs-build-tools
        # https://learn.microsoft.com/visualstudio/install/use-command-line-parameters-to-install-visual-studio
        # https://learn.microsoft.com/visualstudio/install/workload-component-id-vs-community
        winget install --id Microsoft.VisualStudio.2022.BuildTools --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget --override '--force --wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Workload.MSBuildTools --add Microsoft.VisualStudio.Workload.UniversalBuildTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100 --includeRecommended --add Microsoft.VisualStudio.Component.VC.Tools.ARM64'

        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New('Failed to install Visual Studio Build Tools') }

        winget install --id Microsoft.VCRedist.2015+.x64 --exact --accept-package-agreements --accept-source-agreements --uninstall-previous --force --source winget
    }

    # Refresh the environment variables so the current session detects the new dotnet installation
    $Env:Path = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine) + ';' +
    [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::User)

    # https://github.com/Microsoft/vswhere/wiki/Start-Developer-Command-Prompt#using-powershell
    $installationPath = . 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -prerelease -latest -property installationPath
    if ($installationPath -and (Test-Path -Path "$installationPath\Common7\Tools\vsdevcmd.bat" -PathType Leaf)) {
        & "${env:COMSPEC}" /s /c "`"$installationPath\Common7\Tools\vsdevcmd.bat`" -no_logo && set" | ForEach-Object -Process {
            $name, $value = $_ -split '=', 2
            Set-Content -Path env:\"$name" -Value $value -Force
            Write-Host -Object "Setting environment variable: $name=$value"
        }
    }

    # Remove any possible existing directories
    Remove-Item -Path .\MSIXOutputX64 -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\MSIXOutputARM64 -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\MSIXBundleOutput -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\bin -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path .\obj -Recurse -Force -ErrorAction Ignore

    if ($UpdateWorkLoads) {
        # Update the workloads
        dotnet workload update
        dotnet workload config --update-mode workload-set
        dotnet workload update
        if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating the workloads. Exit Code: $LASTEXITCODE") }
    }

    Write-Host -Object "`nChecking .NET info`n`n" -ForegroundColor Magenta
    dotnet --info
    Write-Host -Object "`nListing installed .NET SDKs`n`n" -ForegroundColor Magenta
    dotnet --list-sdks

    function Find-mspdbcmf {
        # "-products *" is necessary to detect BuildTools too
        [string]$VisualStudioPath = . 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -prerelease -latest -property resolvedInstallationPath -products *

        [string]$BasePath = [System.IO.Path]::Combine($VisualStudioPath, 'VC', 'Tools', 'MSVC')

        # Get all subdirectories under the base path
        [System.String[]]$VersionDirs = [System.IO.Directory]::GetDirectories($BasePath)

        # Initialize the highest version with a minimal version value.
        [System.Version]$HighestVersion = [System.Version]::New('0.0.0.0')
        [System.String]$HighestVersionFolder = $null

        # Loop through each directory to find the highest version folder.
        foreach ($Dir in $VersionDirs) {
            # Extract the folder name
            [System.String]$FolderName = [System.IO.Path]::GetFileName($Dir)
            [System.Version]$CurrentVersion = $null
            # Try parsing the folder name as a Version.
            if ([System.Version]::TryParse($FolderName, [ref] $CurrentVersion)) {
                # Compare versions
                if ($CurrentVersion.CompareTo($HighestVersion) -gt 0) {
                    $HighestVersion = $CurrentVersion
                    $HighestVersionFolder = $FolderName
                }
            }
        }

        # If no valid version folder is found
        if (!$HighestVersionFolder) {
            throw [System.IO.DirectoryNotFoundException]::New("No valid version directories found in $BasePath")
        }

        # Combine the base path, the highest version folder, the architecture folder, and the file name.
        [System.String]$mspdbcmfPath = [System.IO.Path]::Combine($BasePath, $HighestVersionFolder, 'bin', 'Hostx64', 'x64', 'mspdbcmf.exe')

        if (![System.IO.File]::Exists($mspdbcmfPath)) {
            throw [System.IO.FileNotFoundException]::New("mspdbcmf.exe not found at $mspdbcmfPath")
        }

        return $mspdbcmfPath
    }

    [string]$mspdbcmfPath = Find-mspdbcmf

    function Find-MSBuild {
        # "-products *" is necessary to detect BuildTools too
        [string]$VisualStudioPath = . 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe' -prerelease -latest -property resolvedInstallationPath -products *

        [string]$MSBuildPath = [System.IO.Path]::Combine($VisualStudioPath, 'MSBuild', 'Current', 'Bin', 'MSBuild.exe')

        if (![System.IO.File]::Exists($MSBuildPath)) {
            throw [System.IO.FileNotFoundException]::New("MSBuild.exe not found at $MSBuildPath")
        }

        return $MSBuildPath
    }

    [string]$MSBuildPath = Find-MSBuild

    #region --- Compile C++ projects ---

    ### ManageDefender

    . $MSBuildPath '..\AppControl Manager\eXclude\C++ WMI Interop\ManageDefender\ManageDefender.slnx' /p:Configuration=Release /p:Platform=x64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building MS Defender solution for X64. Exit Code: $LASTEXITCODE") }

    . $MSBuildPath '..\AppControl Manager\eXclude\C++ WMI Interop\ManageDefender\ManageDefender.slnx' /p:Configuration=Release /p:Platform=arm64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building MS Defender solution for ARM64. Exit Code: $LASTEXITCODE") }

    ### ScheduledTaskManager

    . $MSBuildPath '..\AppControl Manager\eXclude\C++ ScheduledTaskManager\ScheduledTaskManager\ScheduledTaskManager.slnx' /p:Configuration=Release /p:Platform=x64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ScheduledTaskManager solution for X64. Exit Code: $LASTEXITCODE") }

    . $MSBuildPath '..\AppControl Manager\eXclude\C++ ScheduledTaskManager\ScheduledTaskManager\ScheduledTaskManager.slnx' /p:Configuration=Release /p:Platform=arm64 /target:"clean;Rebuild"

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ScheduledTaskManager solution for ARM64. Exit Code: $LASTEXITCODE") }

    #region --- RUST projects ---

    # Uncomment this once stable toolchain supports ehcont security feature, till then we use nightly only
    # rustup default stable
    rustup default nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed setting Rust toolchain to Stable. Exit Code: $LASTEXITCODE") }

    rustup target add aarch64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding aarch64-pc-windows-msvc target to Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup target add x86_64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding x86_64-pc-windows-msvc target to Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup update

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo version

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed checking for Rust version. Exit Code: $LASTEXITCODE") }

    [string]$Current_Location = (Get-Location).Path

    Set-Location -Path '..\AppControl Manager\eXclude\Rust WMI Interop\Device Guard\Program'

    if (Test-Path -PathType Leaf -LiteralPath 'Cargo.lock') {
        Remove-Item -Force -LiteralPath 'Cargo.lock'
    }

    cargo clean

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning the Rust project. Exit Code: $LASTEXITCODE") }

    cargo update --verbose

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo tree

    rustup show active-toolchain

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed showing active Rust toolchain. Exit Code: $LASTEXITCODE") }

    cargo build_x64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building x64 Device Guard Rust project. Exit Code: $LASTEXITCODE") }

    cargo build_arm64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building arm64 Device Guard Rust project. Exit Code: $LASTEXITCODE") }

    Set-Location -Path $Current_Location


    Set-Location -Path '..\AppControl Manager\eXclude\Rust Interop Library'

    if (Test-Path -PathType Leaf -LiteralPath 'Cargo.lock') {
        Remove-Item -Force -LiteralPath 'Cargo.lock'
    }

    rustup toolchain install nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed installing nightly Rust toolchain. Exit Code: $LASTEXITCODE") }

    rustup default nightly

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed setting Rust toolchain to Nightly. Exit Code: $LASTEXITCODE") }

    rustup component add rust-src --toolchain nightly-x86_64-pc-windows-msvc

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed adding rust-src component to Nightly toolchain. Exit Code: $LASTEXITCODE") }

    rustup update

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo version

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed checking for Rust version. Exit Code: $LASTEXITCODE") }

    cargo clean

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed cleaning the Rust project. Exit Code: $LASTEXITCODE") }

    cargo update --verbose

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed updating Rust. Exit Code: $LASTEXITCODE") }

    cargo tree

    rustup show active-toolchain

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed showing active Rust toolchain. Exit Code: $LASTEXITCODE") }

    cargo build_x64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building x64 Rust Interop project. Exit Code: $LASTEXITCODE") }

    cargo build_arm64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ARM64 Rust Interop project. Exit Code: $LASTEXITCODE") }

    Set-Location -Path $Current_Location

    #endregion

    #region --- C# projects ---

    dotnet clean '..\AppControl Manager\eXclude\DISMService\DISMService.slnx' --configuration Release
    dotnet build '..\AppControl Manager\eXclude\DISMService\DISMService.slnx' --configuration Release --verbosity minimal
    dotnet msbuild '..\AppControl Manager\eXclude\DISMService\DISMService.slnx' /p:Platform=x64 /p:PublishProfile=win-x64 /t:Publish -v:minimal

    dotnet clean '..\AppControl Manager\eXclude\DISMService\DISMService.slnx' --configuration Release
    dotnet build '..\AppControl Manager\eXclude\DISMService\DISMService.slnx' --configuration Release --verbosity minimal
    dotnet msbuild '..\AppControl Manager\eXclude\DISMService\DISMService.slnx' /p:Platform=arm64 /p:PublishProfile=win-arm64 /t:Publish -v:minimal

    #endregion

    [string]$CsProjFilePath = (Resolve-Path -Path '.\Harden System Security.csproj').Path

    # https://learn.microsoft.com/dotnet/core/tools/dotnet-build
    # https://learn.microsoft.com/visualstudio/msbuild/msbuild-command-line-reference
    # https://learn.microsoft.com/visualstudio/msbuild/common-msbuild-project-properties

    # Copy the X64 components to the directory before the build starts
    Copy-Item -Path '..\AppControl Manager\eXclude\C++ ScheduledTaskManager\ScheduledTaskManager\x64\Release\ScheduledTaskManager-x64.exe' -Destination '.\CppInterop\ScheduledTaskManager.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\C++ WMI Interop\ManageDefender\x64\Release\ManageDefender-x64.exe' -Destination '.\CppInterop\ManageDefender.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\Rust WMI Interop\Device Guard\Program\target\x86_64-pc-windows-msvc\release\DeviceGuardWMIRetriever-X64.exe' -Destination '.\RustInterop\DeviceGuardWMIRetriever.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\DISMService\OutputX64\DISMService.exe' -Destination '.\DISMService.exe' -Force

    # Generate for X64 architecture
    dotnet clean 'Harden System Security.slnx' --configuration Release
    dotnet build 'Harden System Security.slnx' --configuration Release --verbosity minimal /p:Platform=x64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building x64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    dotnet msbuild 'Harden System Security.slnx' /p:Configuration=Release /p:AppxPackageDir="MSIXOutputX64\" /p:GenerateAppxPackageOnBuild=true /p:Platform=x64 -v:minimal /p:MsPdbCmfExeFullpath=$mspdbcmfPath -bl:X64MSBuildLog.binlog

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed packaging x64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    # Copy the ARM64 components to the directory before the build starts
    Copy-Item -Path '..\AppControl Manager\eXclude\C++ ScheduledTaskManager\ScheduledTaskManager\ARM64\Release\ScheduledTaskManager-ARM64.exe' -Destination '.\CppInterop\ScheduledTaskManager.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\C++ WMI Interop\ManageDefender\ARM64\Release\ManageDefender-ARM64.exe' -Destination '.\CppInterop\ManageDefender.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\Rust WMI Interop\Device Guard\Program\target\aarch64-pc-windows-msvc\release\DeviceGuardWMIRetriever-ARM64.exe' -Destination '.\RustInterop\DeviceGuardWMIRetriever.exe' -Force

    Copy-Item -Path '..\AppControl Manager\eXclude\DISMService\OutputARM64\DISMService.exe' -Destination '.\DISMService.exe' -Force

    # Generate for ARM64 architecture
    dotnet clean 'Harden System Security.slnx' --configuration Release
    dotnet build 'Harden System Security.slnx' --configuration Release --verbosity minimal /p:Platform=ARM64

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed building ARM64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    dotnet msbuild 'Harden System Security.slnx' /p:Configuration=Release /p:AppxPackageDir="MSIXOutputARM64\" /p:GenerateAppxPackageOnBuild=true /p:Platform=ARM64 -v:minimal /p:MsPdbCmfExeFullpath=$mspdbcmfPath -bl:ARM64MSBuildLog.binlog

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("Failed packaging ARM64 Harden System Security project. Exit Code: $LASTEXITCODE") }

    function Get-MSIXFile {
        param(
            [System.String]$BasePath,
            [System.String]$FolderPattern,
            [System.String]$FileNamePattern,
            [System.String]$ErrorMessageFolder,
            [System.String]$ErrorMessageFile
        )
        # Get all subdirectories in the base path matching the folder pattern
        [System.String[]]$Folders = [System.IO.Directory]::GetDirectories($BasePath)
        [System.String]$DetectedFolder = $null
        foreach ($Folder in $Folders) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($Folder, $FolderPattern)) {
                $DetectedFolder = $Folder
                break
            }
        }

        if (!$DetectedFolder) {
            throw [System.InvalidOperationException]::New($ErrorMessageFolder)
        }

        # Get the full path of the first file matching the file name pattern inside the found folder
        [System.String[]]$Files = [System.IO.Directory]::GetFiles($DetectedFolder)
        [System.String]$DetectedFile = $null
        foreach ($File in $Files) {
            if ([System.Text.RegularExpressions.Regex]::IsMatch($File, $FileNamePattern)) {
                $DetectedFile = $File
                break
            }
        }

        if (!$DetectedFile) {
            throw [System.InvalidOperationException]::New($ErrorMessageFile)
        }
        return $DetectedFile
    }

    #region Finding X64 outputs
    [System.String]$FinalMSIXX64Path = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputX64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_x64\.msix' -ErrorMessageFolder 'Could not find the directory for X64 MSIX file' -ErrorMessageFile 'Could not find the X64 MSIX file'
    [System.String]$FinalMSIXX64Name = [System.IO.Path]::GetFileName($FinalMSIXX64Path)
    [System.String]$FinalMSIXX64SymbolPath = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputX64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_x64\.msixsym' -ErrorMessageFolder 'Could not find the directory for X64 symbol file' -ErrorMessageFile 'Could not find the X64 symbol file'
    [System.String]$FinalMSIXX64SymbolName = [System.IO.Path]::GetFileName($FinalMSIXX64SymbolPath)
    #endregion

    #region Finding ARM64 outputs
    [System.String]$FinalMSIXARM64Path = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputARM64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_arm64\.msix' -ErrorMessageFolder 'Could not find the directory for ARM64 MSIX file' -ErrorMessageFile 'Could not find the ARM64 MSIX file'
    [System.String]$FinalMSIXARM64Name = [System.IO.Path]::GetFileName($FinalMSIXARM64Path)
    [System.String]$FinalMSIXARM64SymbolPath = Get-MSIXFile -BasePath ([System.IO.Path]::Combine($PWD.Path, 'MSIXOutputARM64')) -FolderPattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_Test' -FileNamePattern 'Harden System Security_\d+\.\d+\.\d+\.\d+_arm64\.msixsym' -ErrorMessageFolder 'Could not find the directory for ARM64 symbol file' -ErrorMessageFile 'Could not find the ARM64 symbol file'
    [System.String]$FinalMSIXARM64SymbolName = [System.IO.Path]::GetFileName($FinalMSIXARM64SymbolPath)
    #endregion

    #region Detect and Validate File Versions
    [System.Text.RegularExpressions.Regex]$versionRegexX64 = [System.Text.RegularExpressions.Regex]::New('Harden System Security_(\d+\.\d+\.\d+\.\d+)_x64\.msix')

    [System.Text.RegularExpressions.Regex]$versionRegexARM64 = [System.Text.RegularExpressions.Regex]::New('Harden System Security_(\d+\.\d+\.\d+\.\d+)_arm64\.msix')
    [System.Text.RegularExpressions.Match]$MatchX64 = $versionRegexX64.Match($FinalMSIXX64Name)

    [System.Text.RegularExpressions.Match]$MatchARM64 = $versionRegexARM64.Match($FinalMSIXARM64Name)

    if (!$MatchX64.Success) {
        throw [System.InvalidOperationException]::New('Could not detect version from X64 file name')
    }

    if (!$MatchARM64.Success) {
        throw [System.InvalidOperationException]::New('Could not detect version from ARM64 file name')
    }

    [System.String]$versionX64 = $MatchX64.Groups[1].Value

    [System.String]$versionARM64 = $MatchARM64.Groups[1].Value


    if ($versionX64 -ne $versionARM64) {
        throw [System.InvalidOperationException]::New('The versions in X64 and ARM64 files do not match')
    }

    # Craft the file name for the MSIX Bundle file
    [System.String]$FinalBundleFileName = "Harden System Security_$versionX64.msixbundle"
    #endregion

    # Creating the directory where the MSIX packages will be copied to
    [System.String]$MSIXBundleOutput = [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($script:AppControlManagerDirectory, 'MSIXBundleOutput')).FullName

    [System.IO.File]::Copy($FinalMSIXX64Path, [System.IO.Path]::Combine($MSIXBundleOutput, $FinalMSIXX64Name), $true)

    [System.IO.File]::Copy($FinalMSIXARM64Path, [System.IO.Path]::Combine($MSIXBundleOutput, $FinalMSIXARM64Name), $true)

    # The path to the final MSIX Bundle file
    [System.String]$MSIXBundle = [System.IO.Path]::Combine($MSIXBundleOutput, $FinalBundleFileName)

    function Get-MakeAppxPath {
        [System.String]$BasePath = 'C:\Program Files (x86)\Windows Kits\10\bin'

        # Get all subdirectories under the base path
        [System.String[]]$VersionDirs = [System.IO.Directory]::GetDirectories($BasePath)

        # Initialize the highest version with a minimal version value.
        [System.Version]$HighestVersion = [System.Version]::New('0.0.0.0')
        [System.String]$HighestVersionFolder = $null

        # Loop through each directory to find the highest version folder.
        foreach ($Dir in $VersionDirs) {
            # Extract the folder name
            [System.String]$FolderName = [System.IO.Path]::GetFileName($Dir)
            [System.Version]$CurrentVersion = $null
            # Try parsing the folder name as a Version.
            if ([System.Version]::TryParse($FolderName, [ref] $CurrentVersion)) {
                # Compare versions
                if ($CurrentVersion.CompareTo($HighestVersion) -gt 0) {
                    $HighestVersion = $CurrentVersion
                    $HighestVersionFolder = $FolderName
                }
            }
        }

        # If no valid version folder is found
        if (!$HighestVersionFolder) {
            throw [System.IO.DirectoryNotFoundException]::New("No valid version directories found in $BasePath")
        }

        [string]$CPUArch = @{AMD64 = 'x64'; ARM64 = 'arm64' }[$Env:PROCESSOR_ARCHITECTURE]
        if ([System.String]::IsNullOrWhiteSpace($CPUArch)) { throw [System.PlatformNotSupportedException]::New('Only AMD64 and ARM64 architectures are supported.') }

        # Combine the base path, the highest version folder, the architecture folder, and the file name.
        [System.String]$MakeAppxPath = [System.IO.Path]::Combine($BasePath, $HighestVersionFolder, $CPUArch, 'makeappx.exe')

        return $MakeAppxPath
    }

    [System.String]$MakeAppxPath = Get-MakeAppxPath

    if ([System.string]::IsNullOrWhiteSpace($MakeAppxPath)) {
        throw [System.IO.FileNotFoundException]::New('Could not find the makeappx.exe')
    }

    # https://learn.microsoft.com/windows/win32/appxpkg/make-appx-package--makeappx-exe-#to-create-a-package-bundle-using-a-directory-structure
    . $MakeAppxPath bundle /d $MSIXBundleOutput /p $MSIXBundle /o /v

    if ($LASTEXITCODE -ne 0) { throw [System.InvalidOperationException]::New("MakeAppx failed creating the MSIXBundle. Exit Code: $LASTEXITCODE") }

    #Endregion

    Write-Host -Object "X64 MSIX File Path: $FinalMSIXX64Path" -ForegroundColor Green
    Write-Host -Object "X64 MSIX File Name: $FinalMSIXX64Name" -ForegroundColor Green
    Write-Host -Object "X64 Symbols: $FinalMSIXX64SymbolPath" -ForegroundColor Green

    Write-Host -Object "ARM64 MSIX File Path: $FinalMSIXARM64Path" -ForegroundColor Cyan
    Write-Host -Object "ARM64 MSIX File Name: $FinalMSIXARM64Name" -ForegroundColor Cyan
    Write-Host -Object "ARM64 Symbols: $FinalMSIXARM64SymbolPath" -ForegroundColor Cyan

    Write-Host -Object "MSIX Bundle File Path: $MSIXBundle" -ForegroundColor Yellow
    Write-Host -Object "MSIX Bundle File Name: $FinalBundleFileName" -ForegroundColor Yellow

    if ($Workflow) {

        [XML]$CSProjXMLContent = Get-Content -Path $CsProjFilePath -Force
        [string]$MSIXVersion = $CSProjXMLContent.Project.PropertyGroup.FileVersion
        [string]$MSIXVersion = $MSIXVersion.Trim() # It would have trailing whitespaces
        if ([string]::IsNullOrWhiteSpace($FinalMSIXX64Path) -or [string]::IsNullOrWhiteSpace($FinalMSIXX64Name) -or [string]::IsNullOrWhiteSpace($MSIXVersion)) { throw 'Necessary info could not be found' }

        # Write the MSIXVersion to GITHUB_ENV to set it as an environment variable for the entire workflow
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "PACKAGE_VERSION=$MSIXVersion"

        # Saving the details for the MSIX Bundle file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "MSIXBundle_PATH=$MSIXBundle"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "MSIXBundle_NAME=$FinalBundleFileName"

        # Saving the details of the log files
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "X64MSBuildLog_PATH=$((Resolve-Path -Path .\X64MSBuildLog.binlog).Path)"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "ARM64MSBuildLog_PATH=$((Resolve-Path -Path .\ARM64MSBuildLog.binlog).Path)"

        # Saving the details of the X64 symbol file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "X64Symbol_PATH=$FinalMSIXX64SymbolPath"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "X64Symbol_NAME=$FinalMSIXX64SymbolName"

        # Saving the details of the ARM64 symbol file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "ARM64Symbol_PATH=$FinalMSIXARM64SymbolPath"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "ARM64Symbol_NAME=$FinalMSIXARM64SymbolName"

        # https://github.com/microsoft/sbom-tool
        # Generating SBOM
        Invoke-WebRequest -Uri 'https://github.com/microsoft/sbom-tool/releases/latest/download/sbom-tool-win-x64.exe' -OutFile "${Env:RUNNER_TEMP}\sbom-tool.exe"

        # https://github.com/microsoft/sbom-tool/blob/main/docs/sbom-tool-arguments.md
        . "${Env:RUNNER_TEMP}\sbom-tool.exe" generate -b $MSIXBundleOutput -bc .\ -pn 'Harden System Security' -ps 'Violet Hansen' -pv $MSIXVersion -nsb 'https://github.com/HotCakeX/Harden-Windows-Security' -V Verbose -gt true -li true -pm true -D true -lto 80

        # Saving the details of the SBOM file
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value "SBOM_PATH=$MSIXBundleOutput/_manifest/spdx_2.2/manifest.spdx.json"
        Add-Content -Path ($env:GITHUB_ENV, $env:GITHUB_OUTPUT) -Value 'SBOM_NAME=manifest.spdx.json'
    }

    if ($Upload) {
        dotnet clean '..\AppControl Manager\eXclude\PartnerCenter\PartnerCenter.slnx' --configuration Release
        dotnet build '..\AppControl Manager\eXclude\PartnerCenter\PartnerCenter.slnx' --configuration Release --verbosity minimal
        dotnet msbuild '..\AppControl Manager\eXclude\PartnerCenter\PartnerCenter.slnx' /p:Platform=x64 /p:PublishProfile=win-x64 /t:Publish -v:minimal

        [System.String]$TokenEndpoint = $env:PARTNERCENTER_TOKENENDPOINT
        [System.String]$ClientId = $env:PARTNERCENTER_CLIENTID
        [System.String]$ClientSecret = $env:PARTNERCENTER_CLIENTSECRET
        [System.String]$ApplicationId = $env:PARTNERCENTER_APPLICATIONID

        [System.String]$PackageFilePath = $MSIXBundle
        [System.String]$ReleaseNotesFilePath = (Resolve-Path -Path ReleaseNotes.txt).Path

        . '..\AppControl Manager\eXclude\PartnerCenter\X64Output\PartnerCenter.exe' $TokenEndpoint $ClientId $ClientSecret $ApplicationId $PackageFilePath $ReleaseNotesFilePath
    }

    if ($null -ne $Stopwatch) {

        $Stopwatch.Stop()

        $Elapsed = $Stopwatch.Elapsed
        [string]$Result = @"
                  Execution Time:
                  ----------------------------
                  Total Time   : $($Elapsed.ToString('g'))
                  Hours        : $($Elapsed.Hours)
                  Minutes      : $($Elapsed.Minutes)
                  Seconds      : $($Elapsed.Seconds)
                  Milliseconds : $($Elapsed.Milliseconds)
                  ----------------------------
"@

        Write-Host -Object $Result -ForegroundColor Cyan
    }
}

# For GitHub workflow
# Build_HSS -DownloadRepo $false -InstallDeps $false -Workflow $true -UpdateWorkLoads $false -Upload $true
# Local - ARM64 + X64
Build_HSS -DownloadRepo $true -InstallDeps $true -Workflow $false -UpdateWorkLoads $false -Upload $false

```

<br>

</details>

<br>
