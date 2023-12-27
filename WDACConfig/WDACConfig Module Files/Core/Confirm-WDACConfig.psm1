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
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDR/iu8QxMaG3v7
# ZZuvA2wq/cZIFOR9pMrNpebuU4eNNqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgahGeew275Lfwea3aMNvyQi+CULsgd2VamvSXuyhqTtowDQYJKoZIhvcNAQEB
# BQAEggIAddbdS08KhReEJr/iSln4Nal6JKdlEwtz4+KAHumHh628oTN3P1WNvUXM
# uBtfPQCLMtWjwOWSsektMeiQaM7cfGW2LJu15s6GcQdoAn89nt7Qv8Aa3clwZ1eR
# PK9RhnLjeWLVvELfv/JR26iKvJgfa0TUTY2+NBqbZsI563vpa1aw1Ax4oxXI0Hgz
# ByG81dUwsSu6VNXWgTsqhG5UINhkkHMlGcFi7nITCGO91c3iN2Ss21v4rBDlqpGH
# alM0ylwxA+U7Xh+xQNErOK7eFJr0W3vZjIvOgYuZCoJSKuM1TA0krAsvMsdsg9B+
# rWfeFWMWWOHGejiOigh6Zt3EBpSxLb907dmmWxGNSPy1v7Kfb8clTtdLAZdxu7VA
# cJGzaWMu6mQxT0qbSLrRffG6kbzDmdfMkiSu1tPrp+s4jN28GahHZC19MOX99oO/
# b/OfAfFTzLlrbhdN1QRx2y85lpq5lx9iG4D6Ul3LpAiSxgker14LtoUMYYUQuPM0
# cqqBCDIF4ECicoAuNFXrvbgyLD/eRmRn32iLpk2l0lH5ystmuN392Q5NA5+sZGza
# yt96bZvVG5OqastggmZTB8lyxM+eIAwMu4qW4nMdC/syInq7/JggU2UrNJz066EX
# zlWxGT3VGyYtQH5wwPzyCoNeSGtpxZI5IjYkN0GotxbFDlclnvY=
# SIG # End signature block
