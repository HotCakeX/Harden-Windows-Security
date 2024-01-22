Function Remove-CommonWDACConfig {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertCN,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignToolPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$UnsignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$LastUpdateCheck,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelModePolicyTimeOfDeployment
    )
    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Assigning the path to the UserConfigurations.json file
        [System.IO.FileInfo]$Path = "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"

        # Create User configuration folder if it doesn't already exist
        if (-NOT (Test-Path -Path (Split-Path -Path $Path -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $Path -Parent) -Force | Out-Null
            Write-Verbose -Message 'The .WDACConfig folder in the current user folder has been created because it did not exist.'
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT (Test-Path -Path $Path)) {
            New-Item -ItemType File -Path (Split-Path -Path $Path -Parent) -Name (Split-Path -Path $Path -Leaf) -Force | Out-Null
            Write-Verbose -Message 'The UserConfigurations.json file has been created because it did not exist.'
        }

        # Delete the entire User Configs if a more specific parameter wasn't used
        # This method is better than $PSBoundParameters since it also contains common parameters
        if (!$CertCN -And !$CertPath -And !$SignToolPath -And !$UnsignedPolicyPath -And !$SignedPolicyPath -And !$StrictKernelPolicyGUID -And !$StrictKernelNoFlightRootsPolicyGUID -And !$LastUpdateCheck -And !$StrictKernelModePolicyTimeOfDeployment) {
            Remove-Item -Path $Path -Force
            Write-Verbose -Message 'User Configurations for WDACConfig module have been deleted.'

            # set a boolean value that returns from the Process and End blocks as well
            [System.Boolean]$ReturnAndDone = $true
            # Exit the begin block
            Return
        }

        # Read the current user configurations
        [System.Object[]]$CurrentUserConfigurations = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"

        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -Value ''
        }

        # A hashtable to hold the User configurations
        [System.Collections.Hashtable]$UserConfigurationsObject = @{
            SignedPolicyPath                       = ''
            UnsignedPolicyPath                     = ''
            SignToolCustomPath                     = ''
            CertificateCommonName                  = ''
            CertificatePath                        = ''
            StrictKernelPolicyGUID                 = ''
            StrictKernelNoFlightRootsPolicyGUID    = ''
            LastUpdateCheck                        = ''
            StrictKernelModePolicyTimeOfDeployment = ''
        }
    }
    process {
        # Exit the process block
        if ($true -eq $ReturnAndDone) { return }

        if ($SignedPolicyPath) {
            Write-Verbose -Message 'Removing the SignedPolicyPath'
            $UserConfigurationsObject.SignedPolicyPath = ''
        }
        else {
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            Write-Verbose -Message 'Removing the UnsignedPolicyPath'
            $UserConfigurationsObject.UnsignedPolicyPath = ''
        }
        else {
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            Write-Verbose -Message 'Removing the SignToolPath'
            $UserConfigurationsObject.SignToolCustomPath = ''
        }
        else {
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            Write-Verbose -Message 'Removing the CertPath'
            $UserConfigurationsObject.CertificatePath = ''
        }
        else {
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            Write-Verbose -Message 'Removing the CertCN'
            $UserConfigurationsObject.CertificateCommonName = ''
        }
        else {
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            Write-Verbose -Message 'Removing the StrictKernelPolicyGUID'
            $UserConfigurationsObject.StrictKernelPolicyGUID = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            Write-Verbose -Message 'Removing the StrictKernelNoFlightRootsPolicyGUID'
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            Write-Verbose -Message 'Removing the LastUpdateCheck'
            $UserConfigurationsObject.LastUpdateCheck = ''
        }
        else {
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }

        if ($StrictKernelModePolicyTimeOfDeployment) {
            Write-Verbose -Message 'Removing the Strict Kernel-Mode Policy Time Of Deployment'
            $UserConfigurationsObject.StrictKernelModePolicyTimeOfDeployment = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelModePolicyTimeOfDeployment = $CurrentUserConfigurations.StrictKernelModePolicyTimeOfDeployment
        }
    }
    end {
        # Exit the end block
        if ($true -eq $ReturnAndDone) { return }

        $UserConfigurationsJSON = $UserConfigurationsObject | ConvertTo-Json

        try {
            Write-Verbose -Message 'Validating the JSON against the schema'
            [System.Boolean]$IsValid = Test-Json -Json $UserConfigurationsJSON -SchemaFile "$ModuleRootPath\Resources\User Configurations\Schema.json"
        }
        catch {
            Write-Warning -Message "$_`nclearing it."
            Set-Content -Path $Path -Value '' -Force
        }

        if ($IsValid) {
            # Update the User Configurations file
            Write-Verbose -Message 'Saving the changes'
            $UserConfigurationsJSON | Set-Content -Path $Path -Force
        }
        else {
            Throw 'The User Configurations file is not valid.'
        }
    }
    <#
.SYNOPSIS
    Removes common values for parameters used by WDACConfig module
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig
.DESCRIPTION
    Removes common values for parameters used by WDACConfig module from the User Configurations JSON file. If you don't use it with any parameters, then all User Configs will be deleted.
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module, WDACConfig module
.FUNCTIONALITY
    Removes common values for parameters used by WDACConfig module from the User Configurations JSON file. If you don't use it with any parameters, then all User Configs will be deleted.
.PARAMETER SignedPolicyPath
    Removes the SignedPolicyPath from User Configs
.PARAMETER UnsignedPolicyPath
    Removes the UnsignedPolicyPath from User Configs
.PARAMETER CertCN
    Removes the CertCN from User Configs
.PARAMETER SignToolPath
    Removes the SignToolPath from User Configs
.PARAMETER CertPath
    Removes the CertPath from User Configs
.PARAMETER StrictKernelPolicyGUID
    Removes the StrictKernelPolicyGUID from User Configs
.PARAMETER StrictKernelNoFlightRootsPolicyGUID
    Removes the StrictKernelNoFlightRootsPolicyGUID from User Configs
.PARAMETER LastUpdateCheck
    Using DontShow for this parameter which prevents common parameters from being displayed too
.PARAMETER StrictKernelModePolicyTimeOfDeployment
    Removes the StrictKernelModePolicyTimeOfDeployment from User Configs
.INPUTS
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    Remove-CoreWDACConfig -CertCN
.EXAMPLE
    Remove-CoreWDACConfig -CertPath
.EXAMPLE
    Remove-CoreWDACConfig
#>
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOwTJyE1lilpc0
# hd37deRoczCk1PsMUkWSPAn1RHdmpaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgosRTn6/vjqEgVpjkQZamW7pk4mbU0ANBQHok/geB+CAwDQYJKoZIhvcNAQEB
# BQAEggIAm5Nd50jwDmPcaRiZFlEX46z2HQqTF2VsNliZC9JDi3afpRNKG+77+Wpg
# hcX1yMJBfelbz1P3zCSzV4HtuF/mlnWWTaUT+ggClCkO5PQQP10D7UMU/PmyNcPu
# sywp4urfxgq/p9H1Vptyv1ERUpamDXcRRzBXln6NkImxd24JeYZlTTUJIQcJ4VzX
# sCrJMtgdetbRV0ISJzwHm36k5LAV+rXKo8HLtlj+Ivmq6ufOoKVOlGf4sthBHnmc
# gNtyfdq7OZQrGvpGHLh2PB11V9FC2Rz/y7ngGqgYvjToClfG4fBU/wEkSs/uNYxp
# osYhk0yNDKDh18NvQ5B01sDFPQnLKBYzi1m2HmzUpt1CmgPUwQPWs+PB1G2ihUKX
# ixFLl2I1Cdbqdhf1hO3UZV9d9eAtX3Wu9twlHfytT8bA+Wr6/Ugy7AUmFLE3sp4y
# wIzAmRe3GZNI3do8uXB0rJG4hQAskfBT/P4oSFNsKDtqiCpvnaG2lWcbT3JEVXBG
# aI3hh5WUQqEVFP8EY6w1Jtwp1PKN9RunWGHkMEBuh2Ogjj5m29tappyVWXb7lwKt
# ED6l+79I0XcywzVtSOTCbvfBjWUshSkRF+TjeREc2HdHksS09fftmVGGNRZXoTbw
# Rce5Wd/minc9Ss4rXd+30WjcN/KQRP7U3BxgU/JHG/ndY4aslwo=
# SIG # End signature block
