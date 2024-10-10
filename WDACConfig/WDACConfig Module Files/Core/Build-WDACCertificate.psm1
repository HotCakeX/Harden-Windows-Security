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
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }

        # Define a staging area for Build-WDACCertificate cmdlet
        [System.IO.DirectoryInfo]$StagingArea = Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'StagingArea' -AdditionalChildPath 'Build-WDACCertificate'

        # Delete it if it exists already with possible content with previous runs
        if ([System.IO.Directory]::Exists($StagingArea)) {
            Remove-Item -LiteralPath $StagingArea -Recurse -Force
        }

        # Create the staging area for the Build-WDACCertificate cmdlet
        $null = New-Item -Path $StagingArea -ItemType Directory -Force

        # If user entered a common name that is not 'Code Signing Certificate' (which is the default value)
        if ($CommonName -ne 'Code Signing Certificate') {

            # If user did not select a $FileName and it's set to the default value of 'Code Signing Certificate'
            if ($FileName -eq 'Code Signing Certificate') {

                # Set the $FileName to the same value as the $CommonName that the user entered for better user experience
                [System.String]$FileName = $CommonName
            }
        }

        if (!$Password) {

            [WDACConfig.Logger]::Write('Prompting the user to enter a password for the certificate because it was not passed as a parameter.')

            do {
                [System.Security.SecureString]$Password1 = $(Write-ColorfulTextWDACConfig -Color Lavender -InputText 'Enter a password for the certificate (at least 5 characters)'; Read-Host -AsSecureString)
                [System.Security.SecureString]$Password2 = $(Write-ColorfulTextWDACConfig -Color Lavender -InputText 'Confirm your password for the certificate'; Read-Host -AsSecureString)

                # Compare the Passwords and make sure they match
                [System.Boolean]$TheyMatch = [WDACConfig.SecureStringComparer]::Compare($Password1, $Password2)

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

        [WDACConfig.Logger]::Write('Checking if a certificate with the same common name already exists.')
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$DuplicateCerts = foreach ($Item in (Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert)) {
            if ($Item.Subject -ieq "CN=$CommonName") {
                $Item
            }
        }

        if ($DuplicateCerts.Count -gt 0 ) {
            if ($Force -or $PSCmdlet.ShouldContinue('Remove all of them and continue with creating a new certificate?', "$($DuplicateCerts.Count) certificate(s) with the common name '$CommonName' already exist on the system.")) {

                foreach ($Cert in $DuplicateCerts) {
                    $Cert | Remove-Item -Force
                }

            }
            else {
                Throw [System.Data.DuplicateNameException] 'A certificate with the same common name already exists on the system. Please remove it or choose another common name and try again.'
            }
        }
    }
    process {

        Try {

            if ($BuildingMethod -ieq 'Method1') {

                [WDACConfig.Logger]::Write('Building the certificate using Method1.')

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
                [System.String[]]$Lines = foreach ($Line in $CertReqOutput -split "`n") {
                    $Line.Trim()
                }

                # Create a hashtable to store the parsed properties
                [System.Collections.Hashtable]$Properties = @{}

                # Loop through the lines and extract the key-value pairs
                foreach ($Line in $Lines) {
                    # Skip the first line
                    if ($Line -ieq 'Installed Certificate:') {
                        continue
                    }
                    # Check if the line has a colon
                    if ($Line -match ':') {
                        # Split the line by colon with a limit of 2 and trim the whitespace
                        [System.String[]]$Parts = foreach ($Item in ($Line -split ':', 2)) {
                            $Item.Trim()
                        }

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

                [WDACConfig.Logger]::Write('Building the certificate using Method2.')

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

            [WDACConfig.Logger]::Write('Finding the certificate that was just created by its thumbprint')
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$TheCert = foreach ($Cert in (Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert)) {
                if ($Cert.Thumbprint -eq $NewCertificateThumbprint) {
                    $Cert
                }
            }

            [System.IO.FileInfo]$CertificateOutputPath = Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "$FileName.cer"

            [WDACConfig.Logger]::Write("Exporting the certificate (public key only) to $FileName.cer")
            $null = Export-Certificate -Cert $TheCert -FilePath $CertificateOutputPath -Type 'CERT' -Force

            [WDACConfig.Logger]::Write("Exporting the certificate (public and private keys) to $FileName.pfx")
            $null = Export-PfxCertificate -Cert $TheCert -CryptoAlgorithmOption 'AES256_SHA256' -Password $Password -ChainOption 'BuildChain' -FilePath (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "$FileName.pfx") -Force

            [WDACConfig.Logger]::Write('Removing the certificate from the certificate store')
            $TheCert | Remove-Item -Force

            [WDACConfig.Logger]::Write('Importing the certificate to the certificate store again, this time with the private key protected by VSM (Virtual Secure Mode - Virtualization Based Security)')
            $null = Import-PfxCertificate -ProtectPrivateKey 'VSM' -FilePath (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath "$FileName.pfx") -CertStoreLocation 'Cert:\CurrentUser\My' -Password $Password

            [WDACConfig.Logger]::Write('Saving the common name of the certificate to the User configurations')
            $null = [WDACConfig.UserConfiguration]::Set($null, $null, $null, $CommonName, $null, $null, $null, $null , $null)

            [WDACConfig.Logger]::Write('Saving the path of the .cer file of the certificate to the User configurations')
            $null = [WDACConfig.UserConfiguration]::Set($null, $null, $null, $null, $CertificateOutputPath, $null, $null, $null , $null)
        }
        catch {
            throw $_
        }
        Finally {
            Remove-Item -LiteralPath $StagingArea -Recurse -Force
        }
    }
    end {
        Write-ColorfulTextWDACConfig -Color MintGreen -InputText "The certificate with the common name '$CommonName' has been successfully created."
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
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol
.NOTES
    For Method1 INF creation notes:

    2.5.29.19 = {text}ca=0pathlength=0 -> adds basic constraints to the certificate request.
    X500NameFlags = "CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG" -> For setting the encoding to printable string and disabling UTF-8 encoding, required for WDAC policy signing certificate - > https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/create-code-signing-cert-for-appcontrol

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
