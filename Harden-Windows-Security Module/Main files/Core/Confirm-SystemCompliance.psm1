function Confirm-SystemCompliance {
    [CmdletBinding()]
    param (
        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
                $Existing = $CommandAst.FindAll(
                    {
                        $Args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    },
                    $false
                ).Value
                foreach ($Item in [Enum]::GetNames([HardenWindowsSecurity.ComplianceCategories])) {
                    if ($Item -notin $Existing) { $Item }
                }
            })]
        [ValidateScript({
                if ($_ -notin [Enum]::GetNames([HardenWindowsSecurity.ComplianceCategories])) { throw "Invalid Category Name: $_" }
                $true
            })]
        [System.String[]]$Categories,
        [parameter(Mandatory = $false)][Switch]$ExportToCSV,
        [parameter(Mandatory = $false)][Switch]$ShowAsObjectsOnly,
        [parameter(Mandatory = $false)][Switch]$DetailedDisplay,
        [parameter(Mandatory = $false)][Switch]$Offline
    )
    Write-Warning -Message "This module is deprecated.`nPlease use the new Harden System Security App, available on Microsoft Store: https://apps.microsoft.com/detail/9P7GGFL7DX57`nGitHub Document: https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security"
}