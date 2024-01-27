if (!$IsWindows) {
    Throw [System.PlatformNotSupportedException] 'The WDACConfig module only runs on Windows operation systems.'
}

# Specifies that the WDACConfig module requires Administrator privileges
#Requires -RunAsAdministrator

# Create tamper resistant global variables (if they don't already exist) - They are automatically imported in the caller's environment
try {
    if ((Test-Path -Path 'Variable:\MSFTRecommendedBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendedBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -Option 'Constant' -Scope 'Global' -Description 'User Mode block rules' -Force }
    if ((Test-Path -Path 'Variable:\MSFTRecommendedDriverBlockRulesURL') -eq $false) { New-Variable -Name 'MSFTRecommendedDriverBlockRulesURL' -Value 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md' -Option 'Constant' -Scope 'Global' -Description 'Kernel Mode block rules' -Force }
    if ((Test-Path -Path 'Variable:\UserTempDirectoryPath') -eq $false) { New-Variable -Name 'UserTempDirectoryPath' -Value ([System.IO.Path]::GetTempPath()) -Option 'Constant' -Scope 'Global' -Description 'Properly and securely retrieved Temp Directory' -Force }
    if ((Test-Path -Path 'Variable:\UserAccountDirectoryPath') -eq $false) { New-Variable -Name 'UserAccountDirectoryPath' -Value ((Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath) -Option 'Constant' -Scope 'Global' -Description 'Securely retrieved User profile directory' -Force }
    if ((Test-Path -Path 'Variable:\Requiredbuild') -eq $false) { New-Variable -Name 'Requiredbuild' -Value '22621.2428' -Option 'Constant' -Scope 'Script' -Description 'Minimum required OS build number' -Force }
    if ((Test-Path -Path 'Variable:\OSBuild') -eq $false) { New-Variable -Name 'OSBuild' -Value ([System.Environment]::OSVersion.Version.Build) -Option 'Constant' -Scope 'Script' -Description 'Current OS build version' -Force }
    if ((Test-Path -Path 'Variable:\UBR') -eq $false) { New-Variable -Name 'UBR' -Value (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR') -Option 'Constant' -Scope 'Script' -Description 'Update Build Revision (UBR) number' -Force }
    if ((Test-Path -Path 'Variable:\FullOSBuild') -eq $false) { New-Variable -Name 'FullOSBuild' -Value "$OSBuild.$UBR" -Option 'Constant' -Scope 'Script' -Description 'Create full OS build number as seen in Windows Settings' -Force }
    if ((Test-Path -Path 'Variable:\ModuleRootPath') -eq $false) { New-Variable -Name 'ModuleRootPath' -Value ($PSScriptRoot) -Option 'Constant' -Scope 'Global' -Description 'Storing the value of $PSScriptRoot in a global constant variable to allow the internal functions to use it when navigating the module structure' -Force }
    if ((Test-Path -Path 'Variable:\CISchemaPath') -eq $false) { New-Variable -Name 'CISchemaPath' -Value "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd" -Option 'Constant' -Scope 'Global' -Description 'Storing the path to the WDAC Code Integrity Schema XSD file' -Force }

}
catch {
    Throw [System.InvalidOperationException] 'Could not set the required global variables.'
}

# Make sure the current OS build is equal or greater than the required build number
if (-NOT ([System.Decimal]$FullOSBuild -ge [System.Decimal]$Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# Loop through all the relevant files in the module
foreach ($File in (Get-ChildItem -Recurse -File -Path $ModuleRootPath -Include '*.ps1', '*.psm1')) {

    # Get the signature of the current file
    [System.Management.Automation.Signature]$Signature = Get-AuthenticodeSignature -FilePath $File

    # Ensure that they are code signed properly and have not been tampered with.
    if (($Signature.SignerCertificate.Thumbprint -eq '1c1c9082551b43eec17c0301bfb2f27031a4d8c8') -and ($Signature.Status -in 'Valid', 'UnknownError')) {
        # If the file is signed properly, then continue to the next file
    }
    else {
        Throw [System.Security.SecurityException] "The module has been tampered with, signature status of the file $($File.FullName) is $($Signature.Status)"
    }
}

Function Test-CiPolicy {
    <#
    .DESCRIPTION
        Tests the Code Integrity Policy XML file against the Code Integrity Schema file.
    .PARAMETER XmlFile
        The Code Integrity Policy XML file to test.
    .LINK
        https://github.com/HotCakeX/Harden-Windows-Security
    .INPUTS
        [System.IO.FileInfo]
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.IO.FileInfo]$XmlFile
    )

    begin {
        # Check if the schema file exists in the system drive
        if (-NOT (Test-Path -Path $CISchemaPath)) {
            Throw "The Code Integrity Schema file could not be found at: $CISchemaPath"
        }

        # Assign the schema file path to a variable
        [System.IO.FileInfo]$SchemaFilePath = $CISchemaPath
        # Define a script block to handle validation errors
        [System.Management.Automation.ScriptBlock]$ValidationEventHandler = { Throw $args[1].Exception }
    }

    process {
        # Create an XML reader object from the schema file path
        [System.Xml.XmlReader]$XmlReader = [System.Xml.XmlReader]::Create($SchemaFilePath)
        # Read the schema object from the XML reader
        [System.Xml.Schema.XmlSchemaObject]$XmlSchemaObject = [System.Xml.Schema.XmlSchema]::Read($XmlReader, $ValidationEventHandler)

        # Create a variable to store the validation result
        [System.Boolean]$IsValid = $false

        try {
            # Create an XML document object
            [System.Xml.XmlDocument]$Xml = New-Object -TypeName System.Xml.XmlDocument
            # Add the schema object to the XML document
            $Xml.Schemas.Add($XmlSchemaObject) | Out-Null
            # Load the XML file to the XML document
            $Xml.Load($XmlFile)
            # Validate the XML document against the schema object
            $Xml.Validate({
                    # Throw an exception if the validation fails
                    Throw ([PsCustomObject] @{
                            XmlFile   = $XmlFile
                            Exception = $args[1].Exception
                        })
                })

            # If the validation succeeds, set the IsValid variable to $true
            $IsValid = $true
        }
        catch {
            # Rethrow the exception
            Throw $_
        }
        finally {
            # Close the XML reader object
            $XmlReader.Close()
        }
    }
    End {
        # Return the validation result
        Return $IsValid
    }
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUdA3btKqb5sZG
# tIJ3D5ej9n7Vhp96WebYI5mpQniOiaCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgN2GFv7v0pb+E0UjLS9vNOnQgBefmtlT3DMGBBJJtoSgwDQYJKoZIhvcNAQEB
# BQAEggIAKbE2TrdTyzTmnBp4NxkUiEi7rUeXHtaypgT0TEuwVj6Zbh+wNTFh6eH1
# 866csV+30Yi9JGNqaXWlyokz1h9fcOMaespILrAmrF1ZbSUkrUGDzeuP0UDMGSmS
# 4UiP89KEWt1J7ozQVVcBelyzwq3xQHaMobTFYqx7MZpAwcB7w2bWycQ7pVURAGq4
# xCnjOTpAMLMjQOPH7GHOi05VC5w12pZR+dcgZVWiCMVuu+vvZiM9y65OXa6wr3qN
# LXLjUagQoLuryIpiYk3I9LV3o9iET16yasAx3yqrDNXXAgGQeeoMwrXloHuvXSjy
# MzkRBkeNLr5lvQXjjcFHHhhnNonpk9cmPZyPcuJ3RBMSOFqyZxv5KMrjs4q2z7Zh
# 8EgFcnexwoKnjn4W6zZXy1LFv2PqZdxvaxFALjivptbYGPQFRWLYh8su/YourncT
# cvZB8o/Ijp8DXm86m4Nu42HzjQ5TG801qxrDiJ9lCdUlV25t4B3omqgEZVDV1TpP
# aVtS4f/BhcovJ7jz3IOooCgdx3JrjgUMonNjSFDqMiaYzMR1H3MhKv8F2lUEcaP0
# 8W1zhqG1M/7ShsVqI9j7vlcGTveBxb8XqBiThpNqydEqO5G/tP8BTbMznqgmdA35
# SeVawE191YKIxfqAVnnyb3lNXDV4VmKv4hLmUAR04LdLIUXxK1o=
# SIG # End signature block
