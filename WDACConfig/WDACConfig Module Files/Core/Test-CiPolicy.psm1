Function Test-CiPolicy {
    [CmdletBinding()]
    [OutputType([System.Boolean], [System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'XML File')]
        [System.IO.FileInfo]$XmlFile,

        [ValidateScript({ [System.IO.File]::Exists($_) })]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'CIP File')]
        [System.IO.FileInfo]$CipFile
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"
    }

    process {

        # If a CI XML file is being tested
        if ($PSCmdlet.ParameterSetName -eq 'XML File' -and $PSBoundParameters.ContainsKey('XmlFile')) {

            # Check if the schema file exists in the system drive
            if (-NOT ([System.IO.File]::Exists([WDACConfig.GlobalVars]::CISchemaPath))) {
                Throw "The Code Integrity Schema file could not be found at: $([WDACConfig.GlobalVars]::CISchemaPath)"
            }

            # Check if the XML file exists - performing this check here instead of ValidateScript of the parameter produces a better error message when this function is called from within other main cmdlets' parameters.
            if (-NOT ([System.IO.File]::Exists($XmlFile))) {
                Throw "The file $XmlFile does not exist."
            }

            # Assign the schema file path to a variable
            [System.IO.FileInfo]$SchemaFilePath = ([WDACConfig.GlobalVars]::CISchemaPath)
            # Define a script block to handle validation errors
            [System.Management.Automation.ScriptBlock]$ValidationEventHandler = { Throw $args[1].Exception }

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
                [System.Void]$Xml.Schemas.Add($XmlSchemaObject)
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

            # Return the validation result
            Return $IsValid
        }

        # If a CI binary is being tested
        elseif ($PSCmdlet.ParameterSetName -eq 'CIP File' -and $PSBoundParameters.ContainsKey('CipFile')) {

            try {

                # Create a new SignedCms object to store the signed message
                [System.Security.Cryptography.Pkcs.SignedCms]$SignedCryptoMsgSyntax = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms

                # Decode the signed message from the file specified by $CipFile
                # The file is read as a byte array because the SignedCms.Decode() method expects a byte array as input
                # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms.decode
                $SignedCryptoMsgSyntax.Decode((Get-Content -LiteralPath $CipFile -AsByteStream -Raw))

                # Return an array of X509Certificate2 objects that represent the certificates used to sign the message
                Return [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$SignedCryptoMsgSyntax.Certificates

            }
            catch {
                Write-Verbose -Message "The file $CipFile does not contain a valid signature." -Verbose
                Return $null
            }
        }
    }
    <#
.SYNOPSIS
    Tests the Code Integrity Policy XML file against the Code Integrity Schema.
    It can also display the signer information from a signed Code Integrity policy .CIP binary file. Get-AuthenticodeSignature cmdlet does not show signers in .CIP files.
.DESCRIPTION
    The Test-CiPolicy cmdlet can test a Code Integrity (WDAC) Policy.
    If you input a XML file, it will validate it against the Schema file located at: "$Env:SystemDrive\Windows\schemas\CodeIntegrity\cipolicy.xsd"
    and returns a boolean value indicating whether the XML file is valid or not.

    If you input a signed binary Code Integrity Policy file, it will return the signer information from the file.
.PARAMETER XmlFile
    The Code Integrity Policy XML file to test. Supports file picker GUI.
.PARAMETER CipFile
    The binary Code Integrity Policy file to test for signers. Supports file picker GUI.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy
.INPUTS
    [System.IO.FileInfo]
.OUTPUTS
    System.Boolean
    System.Security.Cryptography.X509Certificates.X509Certificate2[]
.EXAMPLE
    Test-CiPolicy -XmlFile "C:\path\to\policy.xml"
.EXAMPLE
    Test-CiPolicy -CipFile "C:\Users\Admin\{C5F45D1A-97F7-42CF-84F1-40755F1AEB97}.cip"
    #>
}
