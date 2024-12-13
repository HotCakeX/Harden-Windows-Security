Function New-WDACConfig {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)][switch]$GetDriverBlockRules,
        [Parameter(Mandatory = $false)][switch]$AutoUpdate
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-WDACConfig')
    Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement
    Try {
        Switch ($PSCmdlet.ParameterSetName) {
            'GetDriverBlockRules' {
                [WDACConfig.BasePolicyCreator]::SetAutoUpdateDriverBlockRules()
                break
            }
            default { Write-Warning -Message 'None of the main parameters were selected.'; break }
        }
    }
    catch {
        throw $_
    }
    Finally {
        if (![WDACConfig.GlobalVars]::DebugPreference) {
            Remove-Item -Path $StagingArea -Recurse -Force
        }
    }
    <#
.SYNOPSIS
    Automate a lot of tasks related to App Control for Business
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig
.PARAMETER GetDriverBlockRules
    Gets the latest Microsoft Recommended Driver Block rules
.PARAMETER AutoUpdate
    Creates a scheduled task that will keep the Microsoft Recommended Driver Block rules up to date by downloading and applying
    the latest block list every 7 days on the system.
#>
}