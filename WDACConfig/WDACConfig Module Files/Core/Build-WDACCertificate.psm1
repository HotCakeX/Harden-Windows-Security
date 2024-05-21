Function Build-WDACCertificate {
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = 'Only use alphanumeric and space characters.')]
        [Parameter(Mandatory = $false)]
        [System.String]$CommonName = 'Code Signing Certificate',

        [ValidatePattern('^(?!.*[\\|/:*?"<>]).*$', ErrorMessage = 'A file name cannot contain any of the following characters \|/:*?"<>')]
        [ValidateCount(1, 250)]
        [Parameter(Mandatory = $false)]
        [System.String]$FileName = 'Code Signing Certificate',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Method1', 'Method2')]
        [System.String]$BuildingMethod = 'Method2',

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))).Length -ge 5
            }, ErrorMessage = 'The password must be at least 5 characters long.')]
        [System.Security.SecureString]$Password,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\Compare-SecureString.psm1"
        )

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        # Define a staging area for Build-WDACCertificate cmdlet
        [System.IO.DirectoryInfo]$StagingArea = Join-Path -Path $UserConfigDir -ChildPath 'StagingArea' -AdditionalChildPath 'Build-WDACCertificate'

        # Delete it if it exists already with possible content with previous runs
        if (Test-Path -PathType Container -LiteralPath $StagingArea) {
            Remove-Item -LiteralPath $StagingArea -Recurse -Force
        }

        # Create the staging area for the Build-WDACCertificate cmdlet
        New-Item -Path $StagingArea -ItemType Directory -Force | Out-Null

        # If user entered a common name that is not 'Code Signing Certificate' (which is the default value)
        if ($CommonName -ne 'Code Signing Certificate') {

            # If user did not select a $FileName and it's set to the default value of 'Code Signing Certificate'
            if ($FileName -eq 'Code Signing Certificate') {

                # Set the $FileName to the same value as the $CommonName that the user entered for better user experience
                [System.String]$FileName = $CommonName
            }
        }

        if (!$Password) {

            Write-Verbose -Message 'Prompting the user to enter a password for the certificate because it was not passed as a parameter.'

            do {
                [System.Security.SecureString]$Password1 = $(Write-ColorfulText -Color Lavender -InputText 'Enter a password for the certificate (at least 5 characters)'; Read-Host -AsSecureString)
                [System.Security.SecureString]$Password2 = $(Write-ColorfulText -Color Lavender -InputText 'Confirm your password for the certificate'; Read-Host -AsSecureString)

                # Compare the Passwords and make sure they match
                [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Password1 -SecureString2 $Password2

                # If the Passwords match and they are at least 5 characters long, assign the Password to the $Password variable
                if ( $TheyMatch -and ($Password1.Length -ge 5) -and ($Password2.Length -ge 5) ) {
                    [System.Security.SecureString]$Password = $Password1
                }
                else {
                    Write-Host -Object 'Please ensure that the Passwords you entered match, and that they are at least 5 characters long.' -ForegroundColor red
                }
            }
            # Repeat this process until the entered Passwords match and they are at least 5 characters long
            until ( $TheyMatch -and ($Password1.Length -ge 5) -and ($Password2.Length -ge 5) )
        }

        Write-Verbose -Message 'Checking if a certificate with the same common name already exists.'
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$DuplicateCerts = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert | Where-Object -FilterScript { $_.Subject -eq "CN=$CommonName" }
        if ($DuplicateCerts.Count -gt 0 ) {
            if ($Force -or $PSCmdlet.ShouldContinue('Remove all of them and continue with creating a new certificate?', "$($DuplicateCerts.Count) certificate(s) with the common name '$CommonName' already exist on the system.")) {

                $DuplicateCerts | ForEach-Object -Process {
                    $_ | Remove-Item -Force
                }
            }
            else {
                Throw [System.Data.DuplicateNameException] 'A certificate with the same common name already exists on the system. Please remove it or choose another common name and try again.'
            }
        }
    }
    process {

        Try {

            if ($BuildingMethod -eq 'Method1') {

                Write-Verbose -Message 'Building the certificate using Method1.'

                [System.String]$Inf = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
X500NameFlags = "CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG"
Subject = "CN=$CommonName"
KeyLength = 4096
KeySpec = 2
KeyUsage = "CERT_DIGITAL_SIGNATURE_KEY_USAGE"
MachineKeySet = False
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
RequestType = Cert
SMIME = False
Exportable = True
ExportableEncrypted = True
KeyAlgorithm = RSA
FriendlyName = "$CommonName"
HashAlgorithm = sha512
ValidityPeriodUnits = 100
ValidityPeriod = Years

[Extensions]
1.3.6.1.4.1.311.21.10 = "{text}oid=1.3.6.1.5.5.7.3.3"
2.5.29.37 = "{text}1.3.6.1.5.5.7.3.3"
2.5.29.19 = {text}ca=0pathlength=0
"@

                # Save the INF content to a random temporary file
                $Inf | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'CertificateCreator.inf') -Force

                # Generate a certificate request using CertReq
                [System.String[]]$CertReqOutput = certreq.exe -new (Join-Path -Path $StagingArea -ChildPath 'CertificateCreator.inf') (Join-Path -Path $StagingArea -ChildPath 'CertificateCreator.req')

                #Region parse-certificate-request-output

                # Split the output by newlines and trim the whitespace
                [System.String[]]$Lines = $CertReqOutput -split "`n" | ForEach-Object -Process { $_.Trim() }

                # Create a hashtable to store the parsed properties
                [System.Collections.Hashtable]$Properties = @{}

                # Loop through the lines and extract the key-value pairs
                foreach ($Line in $Lines) {
                    # Skip the first line
                    if ($Line -eq 'Installed Certificate:') {
                        continue
                    }
                    # Check if the line has a colon
                    if ($Line -match ':') {
                        # Split the line by colon with a limit of 2 and trim the whitespace
                        [System.String[]]$Parts = $Line -split ':', 2 | ForEach-Object -Process { $_.Trim() }
                        # Assign the first part as the key and the second part as the value
                        [System.String]$Key = $Parts[0]
                        [System.String]$Value = $Parts[1]
                        # Add the key-value pair to the hashtable
                        $Properties[$Key] = $Value
                    }
                }
                #Endregion parse-certificate-request-output

                # Save the thumbprint of the certificate to a variable
                [System.String]$NewCertificateThumbprint = $Properties['Thumbprint']
            }

            elseif ($BuildingMethod -eq 'Method2') {

                Write-Verbose -Message 'Building the certificate using Method2.'

                # Create a hashtable of parameter names and values
                [System.Collections.Hashtable]$Params = @{
                    Subject           = "CN=$CommonName"
                    FriendlyName      = $CommonName
                    CertStoreLocation = 'Cert:\CurrentUser\My'
                    KeyExportPolicy   = 'ExportableEncrypted'
                    KeyLength         = '4096'
                    KeyAlgorithm      = 'RSA'
                    HashAlgorithm     = 'sha512'
                    KeySpec           = 'Signature'
                    KeyUsage          = 'DigitalSignature'
                    KeyUsageProperty  = 'Sign'
                    Type              = 'CodeSigningCert'
                    NotAfter          = [System.DateTime](Get-Date).AddYears(100)
                    TextExtension     = @('2.5.29.19={text}CA:FALSE', '2.5.29.37={text}1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.21.10={text}oid=1.3.6.1.5.5.7.3.3')
                }

                # Pass the splatting variable to the command
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$NewCertificate = New-SelfSignedCertificate @params

                # Save the thumbprint of the certificate to a variable
                [System.String]$NewCertificateThumbprint = $NewCertificate.Thumbprint
            }

            Write-Verbose -Message 'Finding the certificate that was just created by its thumbprint'
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$TheCert = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert | Where-Object -FilterScript { $_.Thumbprint -eq $NewCertificateThumbprint }

            [System.IO.FileInfo]$CertificateOutputPath = Join-Path -Path $UserConfigDir -ChildPath "$FileName.cer"

            Write-Verbose -Message "Exporting the certificate (public key only) to $FileName.cer"
            Export-Certificate -Cert $TheCert -FilePath $CertificateOutputPath -Type 'CERT' -Force | Out-Null

            Write-Verbose -Message "Exporting the certificate (public and private keys) to $FileName.pfx"
            Export-PfxCertificate -Cert $TheCert -CryptoAlgorithmOption 'AES256_SHA256' -Password $Password -ChainOption 'BuildChain' -FilePath (Join-Path -Path $UserConfigDir -ChildPath "$FileName.pfx") -Force | Out-Null

            Write-Verbose -Message 'Removing the certificate from the certificate store'
            $TheCert | Remove-Item -Force

            Write-Verbose -Message 'Importing the certificate to the certificate store again, this time with the private key protected by VSM (Virtual Secure Mode - Virtualization Based Security)'
            Import-PfxCertificate -ProtectPrivateKey 'VSM' -FilePath (Join-Path -Path $UserConfigDir -ChildPath "$FileName.pfx") -CertStoreLocation 'Cert:\CurrentUser\My' -Password $Password | Out-Null

            Write-Verbose -Message 'Saving the common name of the certificate to the User configurations'
            Set-CommonWDACConfig -CertCN $CommonName | Out-Null

            Write-Verbose -Message 'Saving the path of the .cer file of the certificate to the User configurations'
            Set-CommonWDACConfig -CertPath $CertificateOutputPath | Out-Null
        }
        Finally {
            Remove-Item -LiteralPath $StagingArea -Recurse -Force
        }
    }
    end {
        Write-ColorfulText -Color MintGreen -InputText "The certificate with the common name '$CommonName' has been successfully created."
    }
    <#
.SYNOPSIS
    Builds a self-signed certificate for use with WDAC.

    All of the outputs are saved in: C:\Program Files\WDACConfig
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-WDACCertificate
.PARAMETER CommonName
    The common name of the certificate. Defaults to 'Code Signing Certificate'.
    If a certificate with the same common name already exists on the system, the user will be asked whether to automatically remove all of them and continue with creating a new certificate.
    This can be automated by passing the -Force switch.

    If you enter a CommonName but do not enter a FileName, the FileName will be set to the same value as the CommonName for better user experience.
.PARAMETER FileName
    The name of the certificate file. Defaults to 'Code Signing Certificate'.
    Selected name should not contain any of the following characters \|/:*?"<>
.PARAMETER BuildingMethod
    The method used to build the certificate.
    Method1 uses CertReq.exe to build the certificate.
    Method2 uses New-SelfSignedCertificate to build the certificate.
.PARAMETER Password
    The password to protect the private key of the certificate, at least 5 characters long.
    If not passed as a parameter, the user will be prompted to enter a password.
.PARAMETER Force
    Forces the removal of any existing certificates with the same common name from the system.
.PARAMETER SkipVersionCheck
    Skips the version check for the module
.DESCRIPTION
    Builds a self-signed certificate for use with WDAC that meets all of the requirements for a WDAC policy signing certificate.
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/create-code-signing-cert-for-wdac
.NOTES
    For Method1 INF creation notes:

    2.5.29.19 = {text}ca=0pathlength=0 -> adds basic constraints to the certificate request.
    X500NameFlags = "CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG" -> For setting the encoding to printable string and disabling UTF-8 encoding, required for WDAC policy signing certificate - > https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/create-code-signing-cert-for-wdac

    For Method2 New-SelfSignedCertificate notes:

    '2.5.29.19={text}CA:FALSE' -> adds basic constraints to the certificate request to make it a non-CA and end entity certificate.
    '2.5.29.37={text}1.3.6.1.5.5.7.3.3' adds the extended key usage for code signing.
    '1.3.6.1.4.1.311.21.10={text}oid=1.3.6.1.5.5.7.3.3' -> adds "[1]Application Certificate Policy:Policy Identifier=Code Signing" as the value for Application Policies extension. The certificate made in CA role in Windows Server (using Code Signing template) also adds this extension.


    Get the value of the Application Policies extension
    ($NewCertificate.Extensions | Where-Object -FilterScript { $_.oid.FriendlyName -eq 'Application Policies' }).Format($false)


    Use certutil -dump -v '.\codesign.cer' to view the certificate properties, such as encoding of the certificate fields like the subject

    The reason for denying to create certificates with common names that already exist in the same store and location on the system is that SignTool.exe can't determine which certificate to use
    when there are multiple certificates with the same common name in the same certificate store so it would either need to randomly choose the best one (using the /a option) or ask the user to provide the SHA1 hash of the certificate to use (using the /sha1 option), which is not secure at all.
    It also can create confusion for users when they have multiple certificates with the same common name in the same certificate store.
.INPUTS
    System.String
    System.Security.SecureString
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    $Password = ConvertTo-SecureString -String 'hotcakex' -AsPlainText
    Build-WDACCertificate -Password $Password -Verbose -Force

    This example builds a self-signed certificate for use with WDAC with the common name 'Code Signing Certificate' and the password 'hotcakex' and files named 'Code Signing Certificate.cer' and 'Code Signing Certificate.pfx'.
.EXAMPLE
    Build-WDACCertificate -Password (ConvertTo-SecureString -String 'hotcakes' -AsPlainText)

    This example builds a self-signed certificate by providing the password in a different way
.EXAMPLE
    $Password = ConvertTo-SecureString -String 'hotcakex' -AsPlainText
    Build-WDACCertificate -Password $Password -Verbose -Force -CommonName 'My WDAC Certificate' -FileName 'My Cert'

    This example builds a self-signed certificate for use with WDAC with the common name 'My WDAC Certificate' and the password 'hotcakex' and files named 'My Cert.cer' and 'My Cert.pfx'.
.EXAMPLE
    Build-WDACCertificate

    This example builds a self-signed certificate for use with WDAC with the common name 'Code Signing Certificate' and files named 'Code Signing Certificate.cer' and 'Code Signing Certificate.pfx'.
    You will be prompted to enter a password.
#>
}

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBJS+4zoTjVPoEz
# vz7VyXn6kvPn2UO55Q22Sg1IKtG4AqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgkfJwnNNGInLycQgHbW8/ypANRPhBTXvgRgI6Sq+aFfAwDQYJKoZIhvcNAQEB
# BQAEggIAhw/H2X+ENOgRYWmnm7zV8QPtdURN7PRR2DjpLmVzOo8N4VeofUJ1+w0/
# y3bbV01AkqcVCLO6jcg8koFWuwpkRJ4ZIGzSeuwlnnCmM9oWiNdKRfxBBeNt/kP0
# 1g9GQUmaUNmNXXStBNsMyehFo4xLgFCiQoqJoLz19eBMZxidS5x8fQDq420mvVh0
# v5qa16zkIKr0CHHe9HvGwF+4J7wvOQLq2RTw8Wceflg71PGMeE99IyuLytoy/1CL
# TIkx6hACvNDMp0UCSoGyazj5uuL+5/XQ1X+eXrlTcrcUzpoyIE7ZJUoWAgnLP4Iw
# UOkoMkOwG9d5si/fuIixpaFyuGpQPSZvhup0zUA7V9zGjZp87pFCWHxadP5cFEdH
# 6SxULwqHDHRL2etMmcUhPMO7YJEsc8Vi9601neVlQBSr3gHhapyyWFfKx73dtsAM
# 1hEtQl8qoxo9CD6xn/3FYw2Prz1fH2/eNYvSU2Otyf49TjdGq82CkQZtB4z8Idju
# 7/c3M3r9Hi0jCaXGOzhyL4rVL0j1NT1E6MsE2Wu5pj1Tjbj+bWFQ/+6Py95OBUMT
# o9JZzQiwj2e+lI2lbmp+GhDge0wxi5WuC4+i/VPjOCw7JyUurb90TfVQmdKQV3T3
# DTpQP9peVod1qUDB9L3tr1C5m5tbBwwrfC5jeLy6/mFUhPEFE8E=
# SIG # End signature block
