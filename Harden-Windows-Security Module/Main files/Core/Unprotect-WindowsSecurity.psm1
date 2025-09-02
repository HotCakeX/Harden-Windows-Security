function Unprotect-WindowsSecurity {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyProcessMitigations')]
        [Switch]$OnlyProcessMitigations,

        [ValidateSet('Downloads-Defense-Measures', 'Dangerous-Script-Hosts-Blocking')]
        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyWDACPolicies')]
        [System.String[]]$WDACPoliciesToRemove,

        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyCountryIPBlockingFirewallRules')]
        [Switch]$OnlyCountryIPBlockingFirewallRules,

        [Parameter(Mandatory = $false)][Switch]$Force
    )
    Write-Warning -Message "This module is deprecated.`nPlease use the new Harden System Security App, available on Microsoft Store: https://apps.microsoft.com/detail/9P7GGFL7DX57`nGitHub Document: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security"
}