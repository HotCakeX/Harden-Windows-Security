Function Get-FileRules {
    <#
    .SYNOPSIS
        Create File Rules based on hash of the files no longer available on the disk and store them in the $Rules variable
    .PARAMETER HashesArray
        The array of hashes of the files no longer available on the disk
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
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
        $i++
    }
    return [System.String]($Rules.Trim())
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-FileRules'
