Function Get-RuleRefs {
    <#
    .SYNOPSIS
        Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
    .INPUTS
        System.Object[]
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [System.Object[]]$HashesArray
    )
    # Importing the $PSDefaultParameterValues to the current session, prior to everything else
    . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

    $HashesArray | ForEach-Object -Begin { $i = 1 } -Process {
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
        $i++
    }
    return [System.String]($RulesRefs.Trim())
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-RuleRefs'
