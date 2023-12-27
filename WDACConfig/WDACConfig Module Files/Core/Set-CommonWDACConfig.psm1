Function Set-CommonWDACConfig {
    [CmdletBinding()]
    Param(
        [ValidateScript({
                # Create an empty array to store the output objects
                [System.String[]]$Output = @()

                # Loop through each certificate that uses RSA algorithm (Because ECDSA is not supported for signing WDAC policies) in the current user's personal store and extract the relevant properties
                foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' | Where-Object -FilterScript { $_.PublicKey.Oid.FriendlyName -eq 'RSA' })) {

                    # Takes care of certificate subjects that include comma in their CN
                    # Determine if the subject contains a comma
                    if ($Cert.Subject -match 'CN=(?<RegexTest>.*?),.*') {
                        # If the CN value contains double quotes, use split to get the value between the quotes
                        if ($matches['RegexTest'] -like '*"*') {
                            $SubjectCN = ($Element.Certificate.Subject -split 'CN="(.+?)"')[1]
                        }
                        # Otherwise, use the named group RegexTest to get the CN value
                        else {
                            $SubjectCN = $matches['RegexTest']
                        }
                    }
                    # If the subject does not contain a comma, use a lookbehind to get the CN value
                    elseif ($Cert.Subject -match '(?<=CN=).*') {
                        $SubjectCN = $matches[0]
                    }
                    $Output += $SubjectCN
                }

                $Output -contains $_
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $false)][System.String]$CertCN,

        [ValidateScript({ (Test-Path -Path $_ -PathType 'Leaf') -and ($_.extension -eq '.cer') }, ErrorMessage = 'The path you selected is not a file path for a .cer file.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$CertPath,

        [ValidateScript({ (Test-Path -Path $_ -PathType 'Leaf') -and ($_.extension -eq '.exe') }, ErrorMessage = 'The path you selected is not a file path for a .exe file.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignToolPath,

        [ValidateScript({
                try {
                    $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                }
                catch {
                    throw 'The selected file is not a valid WDAC XML policy.'
                }

                if (!$RedFlag1 -and !$RedFlag2) {
                    return $True
                }
                else { throw 'The selected policy xml file is Signed, Please select an Unsigned policy.' }

            }, ErrorMessage = 'The selected policy xml file is Signed, Please select an Unsigned policy.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$UnsignedPolicyPath,

        [ValidateScript({
                try {
                    $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                }
                catch {
                    throw 'The selected file is not a valid WDAC XML policy.'
                }

                if ($RedFlag1 -or $RedFlag2) {
                    return $True
                }
                else { throw 'The selected policy xml file is Unsigned, Please select a Signed policy.' }

            }, ErrorMessage = 'The selected policy xml file is Unsigned, Please select a Signed policy.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignedPolicyPath,

        [parameter(Mandatory = $false, DontShow = $true)][System.Guid]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.Guid]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.DateTime]$LastUpdateCheck
    )
    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Create User configuration folder if it doesn't already exist
        if (-NOT (Test-Path -Path "$UserAccountDirectoryPath\.WDACConfig\")) {
            New-Item -ItemType Directory -Path "$UserAccountDirectoryPath\.WDACConfig\" -Force -ErrorAction Stop | Out-Null
            Write-Verbose -Message 'The .WDACConfig folder in the current user folder has been created because it did not exist.'
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT (Test-Path -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json")) {
            New-Item -ItemType File -Path "$UserAccountDirectoryPath\.WDACConfig\" -Name 'UserConfigurations.json' -Force -ErrorAction Stop | Out-Null
            Write-Verbose -Message 'The UserConfigurations.json file in \.WDACConfig\ folder has been created because it did not exist.'
        }

        if (!$CertCN -And !$CertPath -And !$SignToolPath -And !$UnsignedPolicyPath -And !$SignedPolicyPath -And !$StrictKernelPolicyGUID -And !$StrictKernelNoFlightRootsPolicyGUID -And !$LastUpdateCheck) {
            Throw [System.ArgumentException] 'No parameter was selected.'
        }

        # Trying to read the current user configurations
        Write-Verbose -Message 'Trying to read the current user configurations'
        [System.Object[]]$CurrentUserConfigurations = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"

        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Write-Verbose -Message 'The user configurations file exists but is corrupted and has bad values, rewriting it'
            Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -Value ''
        }

        # An object to hold the User configurations
        $UserConfigurationsObject = [PSCustomObject]@{
            SignedPolicyPath                    = ''
            UnsignedPolicyPath                  = ''
            SignToolCustomPath                  = ''
            CertificateCommonName               = ''
            CertificatePath                     = ''
            StrictKernelPolicyGUID              = ''
            StrictKernelNoFlightRootsPolicyGUID = ''
            LastUpdateCheck                     = ''
        }
    }
    process {

        Write-Verbose -Message 'Processing each user configuration property'

        if ($SignedPolicyPath) {
            Write-Verbose -Message 'Saving the supplied Signed Policy path in user configurations.'
            $UserConfigurationsObject.SignedPolicyPath = $SignedPolicyPath.FullName
        }
        else {
            Write-Verbose -Message 'No changes to the Signed Policy path property was detected.'
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            Write-Verbose -Message 'Saving the supplied Unsigned Policy path in user configurations.'
            $UserConfigurationsObject.UnsignedPolicyPath = $UnsignedPolicyPath.FullName
        }
        else {
            Write-Verbose -Message 'No changes to the Unsigned Policy path property was detected.'
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            Write-Verbose -Message 'Saving the supplied SignTool path in user configurations.'
            $UserConfigurationsObject.SignToolCustomPath = $SignToolPath.FullName
        }
        else {
            Write-Verbose -Message 'No changes to the Signtool path property was detected.'
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            Write-Verbose -Message 'Saving the supplied Certificate path in user configurations.'
            $UserConfigurationsObject.CertificatePath = $CertPath.FullName
        }
        else {
            Write-Verbose -Message 'No changes to the Certificate path property was detected.'
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            Write-Verbose -Message 'Saving the supplied Certificate common name in user configurations.'
            $UserConfigurationsObject.CertificateCommonName = $CertCN
        }
        else {
            Write-Verbose -Message 'No changes to the Certificate common name property was detected.'
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            Write-Verbose -Message 'Saving the supplied Strict Kernel policy GUID in user configurations.'
            $UserConfigurationsObject.StrictKernelPolicyGUID = $StrictKernelPolicyGUID
        }
        else {
            Write-Verbose -Message 'No changes to the Strict Kernel policy GUID property was detected.'
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            Write-Verbose -Message 'Saving the supplied Strict Kernel NoFlightRoot policy GUID in user configurations.'
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $StrictKernelNoFlightRootsPolicyGUID
        }
        else {
            Write-Verbose -Message 'No changes to the Strict Kernel NoFlightRoot policy GUID property was detected.'
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            Write-Verbose -Message 'Saving the supplied Last Update Check in user configurations.'
            $UserConfigurationsObject.LastUpdateCheck = $LastUpdateCheck
        }
        else {
            Write-Verbose -Message 'No changes to the Last Update Check property was detected.'
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }
    }
    end {
        # Update the User Configurations file
        Write-Verbose -Message 'Saving the changes'
        $UserConfigurationsObject | ConvertTo-Json | Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"

        Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" | ConvertFrom-Json | Format-List -Property *
    }
    <#
.SYNOPSIS
    Add/Change common values for parameters used by WDACConfig module
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig
.DESCRIPTION
    Add/Change common values for parameters used by WDACConfig module so that you won't have to provide values for those repetitive parameters each time you need to use the WDACConfig module cmdlets.
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module, WDACConfig module
.FUNCTIONALITY
    Add/Change common values for parameters used by WDACConfig module so that you won't have to provide values for those repetitive parameters each time you need to use the WDACConfig module cmdlets.
.PARAMETER SignedPolicyPath
    Path to a Signed WDAC xml policy
.PARAMETER UnsignedPolicyPath
    Path to an Unsigned WDAC xml policy
.PARAMETER CertCN
    Certificate common name
.PARAMETER SignToolPath
    Path to the SignTool.exe
.PARAMETER CertPath
    Path to a .cer certificate file
.PARAMETER StrictKernelPolicyGUID
    GUID of the Strict Kernel mode policy
.PARAMETER StrictKernelNoFlightRootsPolicyGUID
    GUID of the Strict Kernel no Flights root mode policy
.PARAMETER LastUpdateCheck
    Last time the Update policy was checked for updates
    Used internally by the module
.INPUTS
    System.IO.FileInfo
    System.DateTime
    System.Guid
    System.String
.OUTPUTS
    System.Object[]
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertPath' -ScriptBlock $ArgumentCompleterCerFilePathsPicker
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignedPolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'UnsignedPolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCyqCS395RkC3xJ
# LZcQEGxx5Jr+vjcdUbfKDvqP81qJsqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgrx7tM7u2SOXK/GL0xttA7dsZ6asCn7B2vPEECDe1s0cwDQYJKoZIhvcNAQEB
# BQAEggIAn6Cbwsghu1gY9RzQY3O0Jk19hhDc4l1qv6hPv/7RM5XV9klGCOAf/md/
# LSRzyprDqm0F2UlK6yvrofIG3OwPjEDxq4V4hhPcL5xdknMGoLGFETX6fPZWYEic
# 9azy0cj198icbiulu3qKTaFIuedxUPUxFlLjSEAtSib+uY5wHpkfNQ18RUYEPrZa
# 2C10xOcPhDNIiVQMvYX522BAWrDgDnpOGHXRfp1niZlJuyEqD++RG7VJDdPshL2B
# LNumtNP/Py8WqZzpkDuJXv96QwdfnnrJYDUtaBghysdXLQwLnhwC1HYPDlLxS2GL
# rbfk6gogxdDemLNPCnpH+GgX8nuvLQj3wgKh0tEpSaxNTvDZxHJ15XQErpDZURqK
# a6xrYg19mPLKiM1dC6/lC0r8DqrUV0pp5Cfza/GzM5F4RQbi3tJujxgjnx/r+SuS
# e1GVDG1wKh0pHJv7zHPszAGn7CY9g3FOH/bXeZnxnpSHauwSE2L3CeuaptisGx4Z
# HbS2A+GULfqXTYfCh2pI9QNg7jNI2SaqM+TLxfLYfSrfjX64Y1n2LvaT4/KWT3oh
# XAeIsg18e4/m5mUYhu2YlcVJJZVKlOPlnue61HeGvBBHGhkx0RbAge/IdyPJ1fLh
# RBnWt3xnOAV20MGpGbGWE5wIuTXjfN7rrScee/7ssEDAesk5OOs=
# SIG # End signature block
