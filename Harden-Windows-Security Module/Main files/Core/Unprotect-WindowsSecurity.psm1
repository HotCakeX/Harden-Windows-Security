Function Unprotect-WindowsSecurity {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'All'
    )]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyProcessMitigations')]
        [System.Management.Automation.SwitchParameter]$OnlyProcessMitigations,

        [ValidateSet('Downloads-Defense-Measures', 'Dangerous-Script-Hosts-Blocking')]
        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyWDACPolicies')]
        [System.String[]]$WDACPoliciesToRemove,

        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyCountryIPBlockingFirewallRules')]
        [System.Management.Automation.SwitchParameter]$OnlyCountryIPBlockingFirewallRules,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force
    )
    begin {
        if (-NOT ([HardenWindowsSecurity.UserPrivCheck]::IsAdmin())) {
            Throw [System.Security.AccessControl.PrivilegeNotHeldException] 'Administrator'
        }
        $script:ErrorActionPreference = 'Stop'
        [HardenWindowsSecurity.Initializer]::Initialize($VerbosePreference)

        [HardenWindowsSecurity.Logger]::LogMessage('Checking for updates...', [HardenWindowsSecurity.LogTypeIntel]::Information)
        Update-HardenWindowsSecurity -InvocationStatement $MyInvocation.Statement

        # do not prompt for confirmation if the -Force switch is used
        # if both -Force and -Confirm switches are used, the prompt for confirmation will still be correctly shown
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }
    }
    process {
        # Prompt for confirmation before proceeding
        if ($PSCmdlet.ShouldProcess('This PC', 'Removing the Hardening Measures Applied by the Protect-WindowsSecurity Cmdlet')) {

            # doing a try-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
            # or break is passed, clean up will still happen for secure exit
            try {
                Write-Progress -Activity 'Removing protections from Windows' -Status 'Unprotecting' -PercentComplete 50

                [HardenWindowsSecurity.ControlledFolderAccessHandler]::Start()
                Start-Sleep -Seconds 3

                Switch ($True) {
                    $OnlyCountryIPBlockingFirewallRules {
                        [HardenWindowsSecurity.UnprotectWindowsSecurity]::RemoveCountryIPBlockingFirewallRules()
                        break
                    }
                    { $WDACPoliciesToRemove.count -gt 0 } {
                        [HardenWindowsSecurity.UnprotectWindowsSecurity]::RemoveAppControlPolicies(($WDACPoliciesToRemove.Contains('Downloads-Defense-Measures')) ? $true : $false, ($WDACPoliciesToRemove.Contains('Dangerous-Script-Hosts-Blocking')) ? $true : $false)
                        break
                    }
                    $OnlyProcessMitigations {
                        [HardenWindowsSecurity.UnprotectWindowsSecurity]::RemoveExploitMitigations()
                        break
                    }
                    default {
                        [HardenWindowsSecurity.UnprotectWindowsSecurity]::RemoveAppControlPolicies($true, $true)
                        [HardenWindowsSecurity.UnprotectWindowsSecurity]::Unprotect()
                        [HardenWindowsSecurity.UnprotectWindowsSecurity]::RemoveExploitMitigations()
                    }
                }

                Write-Host -Object "$($PSStyle.Foreground.FromRGB(236,68,155))Operation Completed, please restart your computer.$($PSStyle.Reset)"
            }
            finally {
                Write-Progress -Activity 'Completed' -Completed
                [HardenWindowsSecurity.ControlledFolderAccessHandler]::reset()
                [HardenWindowsSecurity.Miscellaneous]::CleanUp()
            }
        }
    }

    <#
.SYNOPSIS
    Removes the hardening measures applied by Protect-WindowsSecurity cmdlet
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module
.DESCRIPTION
    Removes the hardening measures applied by Protect-WindowsSecurity cmdlet
.FUNCTIONALITY
    Removes the hardening measures applied by Protect-WindowsSecurity cmdlet
.PARAMETER OnlyProcessMitigations
    Only removes the Process Mitigations / Exploit Protection settings and doesn't change anything else
.PARAMETER WDACPoliciesToRemove
    Names of the AppControl Policies to remove
.PARAMETER OnlyCountryIPBlockingFirewallRules
    Only removes the country IP blocking firewall rules and doesn't change anything else
.PARAMETER Force
    Suppresses the confirmation prompt
.EXAMPLE
    Unprotect-WindowsSecurity

    Removes all of the security features applied by the Protect-WindowsSecurity cmdlet
.EXAMPLE
    Unprotect-WindowsSecurity -OnlyProcessMitigations

    Removes only the Process Mitigations / Exploit Protection settings and doesn't change anything else
.EXAMPLE
    Unprotect-WindowsSecurity -Force

    Removes all of the security features applied by the Protect-WindowsSecurity cmdlet without prompting for confirmation
.INPUTS
    System.Management.Automation.SwitchParameter
    System.String[]
.OUTPUTS
    System.String
#>
}
