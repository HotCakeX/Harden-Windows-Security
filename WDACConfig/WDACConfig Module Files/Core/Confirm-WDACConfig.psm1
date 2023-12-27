Function Confirm-WDACConfig {
    [CmdletBinding(DefaultParameterSetName = 'List Active Policies')]
    Param(
        [Alias('L')]
        [Parameter(Mandatory = $false, ParameterSetName = 'List Active Policies')][System.Management.Automation.SwitchParameter]$ListActivePolicies,
        [Alias('V')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Verify WDAC Status')][System.Management.Automation.SwitchParameter]$VerifyWDACStatus,
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Check SmartAppControl Status')][System.Management.Automation.SwitchParameter]$CheckSmartAppControlStatus
    )

    DynamicParam {

        # Add the dynamic parameters to the param dictionary
        $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

        if ($PSBoundParameters['ListActivePolicies']) {

            # Create a dynamic parameter for -OnlyBasePolicies
            $OnlyBasePoliciesDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'List Active Policies'
                HelpMessage      = 'Only List Base Policies'
            }

            $ParamDictionary.Add('OnlyBasePolicies', [System.Management.Automation.RuntimeDefinedParameter]::new(
                    'OnlyBasePolicies',
                    [System.Management.Automation.SwitchParameter],
                    [System.Management.Automation.ParameterAttribute[]]@($OnlyBasePoliciesDynamicParameter)
                ))

            # Create a dynamic parameter for -OnlySupplementalPolicies
            $OnlySupplementalPoliciesDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'List Active Policies'
                HelpMessage      = 'Only List Supplemental Policies'
            }

            $ParamDictionary.Add('OnlySupplementalPolicies', [System.Management.Automation.RuntimeDefinedParameter]::new(
                    'OnlySupplementalPolicies',
                    [System.Management.Automation.SwitchParameter],
                    [System.Management.Automation.ParameterAttribute[]]@($OnlySupplementalPoliciesDynamicParameter)
                ))
        }

        # Create a dynamic parameter for -SkipVersionCheck, Adding this parameter as dynamic will make it appear at the end of the parameters
        $SkipVersionCheckDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
            Mandatory        = $false
            # To make this parameter available for all parameter sets
            ParameterSetName = '__AllParameterSets'
            HelpMessage      = 'Skip Version Check'
        }

        $ParamDictionary.Add('SkipVersionCheck', [System.Management.Automation.RuntimeDefinedParameter]::new(
                'SkipVersionCheck',
                [System.Management.Automation.SwitchParameter],
                [System.Management.Automation.ParameterAttribute[]]@($SkipVersionCheckDynamicParameter)
            ))

        return $ParamDictionary
    }

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force

        # Regular parameters are automatically bound to variables in the function scope
        # Dynamic parameters however, are only available in the parameter dictionary, which is why we have to access them using $PSBoundParameters
        # or assign them manually to another variable in the function's scope
        [System.Management.Automation.SwitchParameter]$OnlyBasePolicies = $($PSBoundParameters['OnlyBasePolicies'])
        [System.Management.Automation.SwitchParameter]$OnlySupplementalPolicies = $($PSBoundParameters['OnlySupplementalPolicies'])
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck = $($PSBoundParameters['SkipVersionCheck'])

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        # Script block to show only non-system Base policies
        [System.Management.Automation.ScriptBlock]$OnlyBasePoliciesBLOCK = {
            [System.Object[]]$BasePolicies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }
            Write-ColorfulText -Color Lavender -InputText "`nThere are currently $(($BasePolicies.count)) Non-system Base policies deployed"
            $BasePolicies
        }
        # Script block to show only non-system Supplemental policies
        [System.Management.Automation.ScriptBlock]$OnlySupplementalPoliciesBLOCK = {
            [System.Object[]]$SupplementalPolicies = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -ne $_.BasePolicyID) }
            Write-ColorfulText -Color Lavender -InputText "`nThere are currently $(($SupplementalPolicies.count)) Non-system Supplemental policies deployed`n"
            $SupplementalPolicies
        }

        # If no main parameter was passed, run all of them
        if (!$ListActivePolicies -and !$VerifyWDACStatus -and !$CheckSmartAppControlStatus) {
            $ListActivePolicies = $true
            $VerifyWDACStatus = $true
            $CheckSmartAppControlStatus = $true
        }
    }

    process {
        if ($ListActivePolicies) {
            if ($OnlyBasePolicies) { &$OnlyBasePoliciesBLOCK }
            if ($OnlySupplementalPolicies) { &$OnlySupplementalPoliciesBLOCK }
            if (!$OnlyBasePolicies -and !$OnlySupplementalPolicies) { &$OnlyBasePoliciesBLOCK; &$OnlySupplementalPoliciesBLOCK }
        }

        if ($VerifyWDACStatus) {
            Write-Verbose -Message 'Checking the status of WDAC using Get-CimInstance'
            Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -Property *codeintegrity* | Format-List
            Write-ColorfulText -Color Lavender -InputText "2 -> Enforced`n1 -> Audit mode`n0 -> Disabled/Not running`n"
        }

        if ($CheckSmartAppControlStatus) {
            Write-Verbose -Message 'Checking the status of Smart App Control using Get-MpComputerStatus'
            Get-MpComputerStatus | Select-Object -Property SmartAppControlExpiration, SmartAppControlState
            if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                Write-ColorfulText -Color Pink -InputText "`nSmart App Control is in Evaluation mode."
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'On') {
                Write-ColorfulText -Color Pink -InputText "`nSmart App Control is turned on."
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'Off') {
                Write-ColorfulText -Color Pink -InputText "`nSmart App Control is turned off."
            }
        }
    }

    <#
.SYNOPSIS
    Shows the status of WDAC on the system, lists the currently deployed policies and shows the details about each of them.
    It can also show the status of Smart App Control.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig
.DESCRIPTION
    Using official Microsoft methods, Show the status of WDAC (Windows Defender Application Control) on the system, list the current deployed policies and show details about each of them.
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Using official Microsoft methods, Show the status of WDAC (Windows Defender Application Control) on the system, list the current deployed policies and show details about each of them.
.PARAMETER ListActivePolicies
    Lists the currently deployed policies and shows details about each of them
.PARAMETER VerifyWDACStatus
    Shows the status of WDAC (Windows Defender Application Control) on the system
.PARAMETER CheckSmartAppControlStatus
    Checks the status of Smart App Control and reports the results on the console
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.EXAMPLE
    Confirm-WDACConfig -ListActivePolicies -OnlyBasePolicies
.EXAMPLE
    Confirm-WDACConfig -ListActivePolicies -OnlySupplementalPolicies
.EXAMPLE
    Confirm-WDACConfig -ListActivePolicies
.INPUTS
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
    System.Object
#>
}

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDR/iu8QxMaG3v7
# ZZuvA2wq/cZIFOR9pMrNpebuU4eNNqCCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
# /t9ITGbLAAAAAAAHMA0GCSqGSIb3DQEBDQUAMEQxEzARBgoJkiaJk/IsZAEZFgNj
# b20xFDASBgoJkiaJk/IsZAEZFgRCaW5nMRcwFQYDVQQDEw5CaW5nLVNFUlZFUi1D
# QTAgFw0yMzEyMjcwODI4MDlaGA8yMTMzMTIyNzA4MzgwOVoweDELMAkGA1UEBhMC
# VUsxFjAUBgNVBAoTDVNweU5ldEdpcmwgQ28xKjAoBgNVBAMTIUhvdENha2VYIENv
# ZGUgU2lnbmluZyBDZXJ0aWZpY2F0ZTElMCMGCSqGSIb3DQEJARYWU3B5bmV0Z2ly
# bEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANsD
# szHV9Ea21AhOw4a35P1R30HHtmz+DlWKk/a4FvYQivl9dd+f+SZaybl0O96H6YNp
# qLnx7KD9TSEBbB+HxjE39GfWoX2R1VlPaDqkbGMA0XmnUB+/5CsbhktY4gbvJpW5
# LWXk0xUmCSvLMs7eiuBOGNs3zw5xVVNhsES6/aYMCWREI9YPTVbh7En6P4uZOisy
# K2tZtkSe/TXabfr1KtNhELr3DpTNtJBMBLzhz8d6ztJExKebFqpiaNqF7TpTOTRI
# 4P02k6u6lsWMz/rH9mMHdGSyBJ3DEyJGL9QT4jO4BFLHsxHuWTpjxnqxZNjwLTjB
# NEhH+VcKIIy2iWHfWwK2Nwr/3hzDbfqsWrMrXvvCqGpei+aZTxyplbMPpmd5myKo
# qLI58zc7cMi/HuAbbjo1YWxd/J1shHifMfhXfuncjHr7RTGC3BaEzwirQ12t1Z2K
# Zn2AhLnhSElbgZppt+WS4bmzT6L693srDxSMcBpRcu8NyDteLVCmgfBGXDdfAKEZ
# KXPi9liV0b66YQWnBp9/3bYwtYTh5VwjfSVAMfWsrMpIeGmvGUcsnQCqCxCulHKX
# onoYmbyotyOiXObXVgzB2G0k+VjxiFTSb1ENf3GJV1FJbzbch/p/tASY9w2L7kT/
# l+/Nnp4XOuPDYhm/0KWgEH7mUyq4KkP/BG/on7Q5AgMBAAGjggJ+MIICejA8Bgkr
# BgEEAYI3FQcELzAtBiUrBgEEAYI3FQjinCqC5rhWgdmZEIP42AqB4MldgT6G3Kk+
# mJFMAgFkAgEOMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0O
# BBYEFFr7G/HfmP3Om/RStyhaEtEFmSYKMB8GA1UdEQQYMBaBFEhvdGNha2V4QG91
# dGxvb2suY29tMB8GA1UdIwQYMBaAFChQ2b1sdIHklqMDHsFKcUCX6YREMIHIBgNV
# HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPUJpbmctU0VSVkVSLUNBLENO
# PVNlcnZlcixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
# dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1CaW5nLERDPWNvbT9jZXJ0aWZpY2F0
# ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
# UG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxkYXA6Ly8v
# Q049QmluZy1TRVJWRVItQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QmluZyxEQz1jb20/
# Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
# b3JpdHkwDQYJKoZIhvcNAQENBQADggIBAE/AISQevRj/RFQdRbaA0Ffk3Ywg4Zui
# +OVuCHrswpja/4twBwz4M58aqBSoR/r9GZo69latO74VMmki83TX+Pzso3cG5vPD
# +NLxwAQUo9b81T08ZYYpdWKv7f+9Des4WbBaW9AGmX+jJn+JLAFp+8V+nBkN2rS9
# 47seK4lwtfs+rVMGBxquc786fXBAMRdk/+t8G58MZixX8MRggHhVeGc5ecCRTDhg
# nN68MhJjpwqsu0sY2NeKz5gMSk6wvt+NDPcfSZyNo1uSEMKTl/w5UH7mnrv0D4fZ
# UOY3cpIwbIagwdBuFupKG/m1I2LXZdLgGfOtZyZyw+c5Kd0KlMxonBiVoqN7PvoA
# 7sfwDI7PMLMQ3mseFbIpSUQGXHGeyouN1jF5ciySfHnW1goiG8tfDKNAT7WEz+ZT
# c1iIH+lCDUV/LmFD1Bvj2A9Q01C9BsScH+9vb2CnIwaSmfFRI6PY9cKOEHdy/ULi
# hp72QBd6W6ZQMZWXI5m48DdiKlQGA1aCdNN6+C0of43a7L0rAtLPYKySpd6gc34I
# h7/DgGLqXg0CO4KtbGdEWfKHqvh0qYLRmo/obhyVMYib4ceKrCcdc9aVlng/25nE
# ExvokF0vVXKSZkRUAfNHmmfP3lqbjABHC2slbStolocXwh8CoN8o2iOEMnY/xez0
# gxGYBY5UvhGKMYIDDTCCAwkCAQEwWzBEMRMwEQYKCZImiZPyLGQBGRYDY29tMRQw
# EgYKCZImiZPyLGQBGRYEQmluZzEXMBUGA1UEAxMOQmluZy1TRVJWRVItQ0ECE1QA
# AAAHOCn+30hMZssAAAAAAAcwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgahGeew275Lfw
# ea3aMNvyQi+CULsgd2VamvSXuyhqTtowDQYJKoZIhvcNAQEBBQAEggIAGAVuCDMZ
# KG4vCB0fkIlqDgKeqFk9f+J96j4SU7euVcBuFqne4EdSLANlwKt5GopkLvFdKgAu
# 2zYS3JpSdO10WnCCjWvJdRKqPEaPBs14eNxVWRuKaCN8P4GqI9Ko/vrAL7lQDXun
# rkh/gvthR16tcl/tJd1AfYugwsC11BAJV2ymShR1xA7EWsLEnDxtMpZFlkznAiDW
# yT+/7VnvjHXdBdxqvlcaMGKEqjmqrOhWFhrdIx1xlRLmhLuOpNR1moBElVC1blTk
# bY17jU7EcCNj/PMIDqocmlYIOO082+BHomyGSJmg8nmhUS4sAvxX1Iub7HvKBUUB
# WH6dxLIc4RfxsNr+g49ZZm3+7YSBZvrquh05yrnbWnwJ40hIj6eDkjWtkAsgwCyJ
# jATHT6Twdp0K5+/dw6/q303iQ5LnZJ6+zSu+YowvTHfEhwiI2HA6qIRstAdTktIL
# YB/CoFXT6grHsOu2jQi/5cYB210iEGCXWhawi1JrGXsKPqjqgW/RNOd1CNEP0elX
# 2wlyqVfur6dA4pBFe3hm4xkYK85cQuxEHWeKljy9pTNaTmR0ig3HHP9yDNbcTtRC
# BycYy+REbhfEqzRPvZoLuZLQ7D3m32gjL+YQejZseAhANxHpIOf2woUTipVZuD7t
# 7kCMN/wkmj2wIGYzZ3JAm9KAnHsIC1EAaWw=
# SIG # End signature block
