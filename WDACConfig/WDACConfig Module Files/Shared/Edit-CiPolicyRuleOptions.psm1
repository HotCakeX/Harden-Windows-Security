Function Edit-CiPolicyRuleOptions {
    <#
    .SYNOPSIS
        Configures the Policy rule options in a given XML file
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]

    param (
        [ValidateSet('Base', 'Supplemental', 'TestMode', 'Base-KernelMode', 'Base-ISG')]
        [Parameter(Mandatory = $true)]
        [System.String]$Action,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$XMLFile
    )

    Begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Configuring the policy rule options'
    }

    Process {
        Switch ($Action) {
            'Base' {
                @(0, 2, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                @(3, 4, 8, 9, 10, 13, 14, 15, 18) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'Base-ISG' {
                @(0, 2, 6, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                @(3, 4, 8, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'Base-KernelMode' {
                @(2, 6, 16, 17, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                @(0, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 18, 19) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'Supplemental' {
                Set-RuleOption -FilePath $XMLFile -Option 18
                @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ -Delete }
                break
            }
            'TestMode' {
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $XMLFile -Option $_ }
                break
            }
        }
    }
    End {
        Set-HVCIOptions -Strict -FilePath $XMLFile
    }
}
Export-ModuleMember -Function 'Edit-CiPolicyRuleOptions'
