Function Build-WDACCertificate {
    [CmdletBinding()]
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

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Compare-SecureString.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

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

        if ($BuildingMethod -eq 'Method1') {

            Write-Verbose -Message 'Building the certificate using Method1.'

            [System.String]$Inf = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
X500NameFlags = "CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG"
Subject = "CN=Code Signing Certificate"
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
FriendlyName = "Code Signing Certificate"
HashAlgorithm = sha512
ValidityPeriodUnits = 100
ValidityPeriod = Years

[Extensions]
2.5.29.37 = "{text}1.3.6.1.5.5.7.3.3"
2.5.29.19 = {text}ca=0pathlength=0
"@

            [System.Guid]$RandomGUID = [System.Guid]::NewGuid()

            # Save the INF content to a random temporary file
            $Inf | Out-File -FilePath ".\$RandomGUID.inf" -Force

            # Generate a certificate request using CertReq
            [System.String[]]$CertReqOutput = certreq.exe -new ".\$RandomGUID.inf" ".\$RandomGUID.req"

            # Remove the temporary files after the certificate has been generated
            Remove-Item -Path ".\$RandomGUID.req", ".\$RandomGUID.inf" -Force

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

        Write-Verbose -Message "Exporting the certificate (public key only) to $FileName.cer"
        Export-Certificate -Cert $TheCert -FilePath ".\$FileName.cer" -Type 'CERT' -Force | Out-Null

        Write-Verbose -Message "Exporting the certificate (public and private keys) to $FileName.pfx"
        Export-PfxCertificate -Cert $TheCert -CryptoAlgorithmOption 'AES256_SHA256' -Password $Password -ChainOption 'BuildChain' -FilePath ".\$FileName.pfx" -Force | Out-Null

        Write-Verbose -Message 'Removing the certificate from the certificate store'
        $TheCert | Remove-Item -Force

        Write-Verbose -Message 'Importing the certificate to the certificate store again, this time with the private key protected by VSM (Virtual Secure Mode - Virtualization Based Security)'
        Import-PfxCertificate -ProtectPrivateKey 'VSM' -FilePath ".\$FileName.pfx" -CertStoreLocation 'Cert:\CurrentUser\My' -Password $Password | Out-Null

        Write-Verbose -Message 'Saving the common name of the certificate to the User configurations'
        Set-CommonWDACConfig -CertCN $CommonName | Out-Null

        Write-Verbose -Message 'Saving the path of the .cer file of the certificate to the User configurations'
        Set-CommonWDACConfig -CertPath ".\$FileName.cer" | Out-Null
    }
    <#
.SYNOPSIS
    Builds a self-signed certificate for use with WDAC.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Build-WDACCertificate
.PARAMETER CommonName
    The common name of the certificate. Defaults to 'Code Signing Certificate'.
    If a certificate with the same common name already exists on the system, the user will be asked whether to automatically remove all of them and continue with creating a new certificate.
    This can be automated by passing the -Force switch.
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
    ($NewCertificate.Extensions | Where-Object { $_.oid.FriendlyName -eq 'Application Policies' }).Format($false)


    Use certutil -dump -v '.\codesign.cer' to view the certificate properties, such as encoding of the certificate fields like the subject
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
