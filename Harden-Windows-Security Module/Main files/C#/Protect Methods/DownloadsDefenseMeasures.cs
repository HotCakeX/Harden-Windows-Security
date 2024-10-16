#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class DownloadsDefenseMeasures
    {
        public static void Invoke()
        {

            ChangePSConsoleTitle.Set("🎇 Downloads Defense Measures");

            HardenWindowsSecurity.Logger.LogMessage("Running the Downloads Defense Measures category", LogTypeIntel.Information);

            // PowerShell script with embedded {UserValue} directly in the string using @""
            string script = $@"
$VerbosePreference = 'Continue'
$script:ErrorActionPreference = 'Stop'

#region Installation And Update

# a flag indicating the WDACConfig module must be downloaded and installed on the system
[System.Boolean]$ShouldInstallWDACConfigModule = $true

Write-Verbose -Message 'Getting the latest available version number of the WDACConfig module'
[System.Version]$WDACConfigLatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt'

Write-Verbose -Message 'Getting the latest available version of the WDACConfig module from the local system, if it exists'
[System.Management.Automation.PSModuleInfo]$WDACConfigModuleLocalStatus = Get-Module -ListAvailable -Name 'WDACConfig' -Verbose:$false | Sort-Object -Property Version -Descending | Select-Object -First 1

# If the WDACConfig module is already installed on the system and its version is greater than or equal to the latest version available on GitHub repo then don't install it again
if (($null -ne $WDACConfigModuleLocalStatus) -and ($WDACConfigModuleLocalStatus.count -gt 0)) {{
    if ($WDACConfigModuleLocalStatus.Version -ge $WDACConfigLatestVersion) {{
        $ShouldInstallWDACConfigModule = $false
        Write-Verbose -Message 'Skipping WDACConfig module installation, it is already installed.'
    }}
    else {{
        [System.String]$ReasonToInstallWDACConfigModule = ""the installed WDACConfig module version $($WDACConfigModuleLocalStatus.Version) is less than the latest available version $($WDACConfigLatestVersion)""
        Write-Verbose -Message 'Removing the WDACConfig module'
        try {{
            $null = Uninstall-Module -Name 'WDACConfig' -Force -Verbose:$false -AllVersions
        }}
        catch {{}}
    }}
}}
else {{
    [System.String]$ReasonToInstallWDACConfigModule = 'it is not installed on the system'
}}

if ($ShouldInstallWDACConfigModule) {{
    Write-Verbose -Message ""Installing the WDACConfig module because $ReasonToInstallWDACConfigModule""
    Install-Module -Name 'WDACConfig' -Force -Verbose:$false -Scope 'AllUsers' -RequiredVersion $WDACConfigLatestVersion
}}

#endregion Installation And Update

Write-Verbose -Message 'Getting the currently deployed base policy names'
$CurrentBasePolicyNames = [System.Collections.Generic.HashSet[System.String]](((&""$env:SystemDrive\Windows\System32\CiTool.exe"" -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript {{ ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }}).FriendlyName)

# Only deploy the Downloads-Defense-Measures policy if it is not already deployed
if (($null -eq $CurrentBasePolicyNames) -or (-NOT ($CurrentBasePolicyNames.Contains('Downloads-Defense-Measures')))) {{

    Write-Verbose -Message 'Detecting the Downloads folder path on system'
    [System.IO.FileInfo]$DownloadsPathSystem = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.path
    Write-Verbose -Message ""The Downloads folder path on system is $DownloadsPathSystem""

    # Checking if the Edge preferences file exists
    if ([System.IO.File]::Exists(""$env:SystemDrive\Users\{GlobalVars.userName}\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"")) {{

        Write-Verbose -Message 'Detecting the Downloads path in Edge'
        [PSCustomObject]$CurrentUserEdgePreference = ConvertFrom-Json -InputObject (Get-Content -Raw -Path ""$env:SystemDrive\Users\{GlobalVars.userName}\AppData\Local\Microsoft\Edge\User Data\Default\Preferences"")
        [System.IO.FileInfo]$DownloadsPathEdge = $CurrentUserEdgePreference.savefile.default_directory

        # Ensure there is an Edge browser profile and it was initialized
        if ((-NOT [System.String]::IsNullOrWhitespace($DownloadsPathEdge.FullName))) {{

            Write-Verbose -Message ""The Downloads path in Edge is $DownloadsPathEdge""

            # Display a warning for now
            if ($DownloadsPathEdge.FullName -ne $DownloadsPathSystem.FullName) {{
                Write-Warning -Message ""The Downloads path in Edge ($($DownloadsPathEdge.FullName)) is different than the system's Downloads path ($($DownloadsPathSystem.FullName))""
            }}
        }}
    }}

    Write-Verbose -Message 'Creating and deploying the Downloads-Defense-Measures policy'
    New-DenyWDACConfig -PathWildCards -PolicyName 'Downloads-Defense-Measures' -FolderPath ""$DownloadsPathSystem\*"" -Deploy -Verbose:$Verbose -SkipVersionCheck -EmbeddedVerboseOutput

}}
else {{
    Write-Verbose -Message 'The Downloads-Defense-Measures policy is already deployed'
}}
";

            _ = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(script);
        }
    }
}
