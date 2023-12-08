Function Get-BlockRulesMeta {
    <#
    .SYNOPSIS
        Gets the latest Microsoft Recommended block rules, removes its allow all rules and sets HVCI to strict
    .INPUTS
        System.Void
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param ()

    [System.String]$Rules = (Invoke-WebRequest -Uri $MSFTRecommendeBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1' -replace '<Allow\sID="ID_ALLOW_A_[12]".*/>|<FileRuleRef\sRuleID="ID_ALLOW_A_[12]".*/>', ''
    $Rules | Out-File -FilePath '.\Microsoft recommended block rules TEMP.xml' -Force
    # Removing empty lines from policy file
    Get-Content -Path '.\Microsoft recommended block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File -FilePath '.\Microsoft recommended block rules.xml' -Force
    Remove-Item -Path '.\Microsoft recommended block rules TEMP.xml' -Force
    Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete
    Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'
    return [PSCustomObject]@{
        PolicyFile = 'Microsoft recommended block rules.xml'
    }
}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'Get-BlockRulesMeta' -Verbose:$false
