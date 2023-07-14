# Defining a custom object to store the signer information
class Signer {
    [string]$ID
    [string]$Name
    [string]$CertRoot
    [string]$CertPublisher
}
  
# Function that takes an XML file path as input and returns an array of Signer objects
function Get-SignerInfo {
    param(
        [Parameter(Mandatory = $true)][string]$XmlFilePath
    )
  
    # Load the XML file and select the Signer nodes
    $xml = [xml](Get-Content $XmlFilePath)
    $Signers = $xml.SiPolicy.Signers.Signer
  
    # Create an empty array to store the output
    $output = @()
  
    # Loop through each Signer node and extract the information
    foreach ($signer in $signers) {
        # Create a new Signer object and assign the properties
        $SignerObj = [Signer]::new()
        $SignerObj.ID = $signer.ID
        $SignerObj.Name = $signer.Name
        $SignerObj.CertRoot = $signer.CertRoot.Value
        $SignerObj.CertPublisher = $signer.CertPublisher.Value
  
        # Add the Signer object to the output array
        $output += $SignerObj
    }
  
    # Return the output array
    return $output
}

# Function to calculate the TBS of a certificate
function Get-TBSCertificate {
    param ($Cert)
    
    # Get the raw data of the certificate
    $RawData = $Cert.RawData
    
    # Create an ASN.1 reader to parse the certificate
    $AsnReader = New-Object System.Formats.Asn1.AsnReader -ArgumentList $RawData, ([System.Formats.Asn1.AsnEncodingRules]::DER)
    
    # Read the certificate sequence
    $Certificate = $AsnReader.ReadSequence()
    
    # Read the TBS (To be signed) value of the certificate
    $TbsCertificate = $Certificate.ReadEncodedValue()
    
    # Read the signature algorithm sequence
    $SignatureAlgorithm = $Certificate.ReadSequence()
    
    # Read the algorithm OID of the signature
    $AlgorithmOid = $SignatureAlgorithm.ReadObjectIdentifier()
    
    # Define a hash function based on the algorithm OID
    switch ($AlgorithmOid) {
        "1.2.840.113549.1.1.4" { $HashFunction = [System.Security.Cryptography.MD5]::Create() }
        "1.2.840.10040.4.3" { $HashFunction = [System.Security.Cryptography.SHA1]::Create() }
        "2.16.840.1.101.3.4.3.2" { $HashFunction = [System.Security.Cryptography.SHA256]::Create() }
        "2.16.840.1.101.3.4.3.3" { $HashFunction = [System.Security.Cryptography.SHA384]::Create() }
        "2.16.840.1.101.3.4.3.4" { $HashFunction = [System.Security.Cryptography.SHA512]::Create() }
        "1.2.840.10045.4.1" { $HashFunction = [System.Security.Cryptography.SHA1]::Create() }
        "1.2.840.10045.4.3.2" { $HashFunction = [System.Security.Cryptography.SHA256]::Create() }
        "1.2.840.10045.4.3.3" { $HashFunction = [System.Security.Cryptography.SHA384]::Create() }
        "1.2.840.10045.4.3.4" { $HashFunction = [System.Security.Cryptography.SHA512]::Create() }
        "1.2.840.113549.1.1.5" { $HashFunction = [System.Security.Cryptography.SHA1]::Create() }
        "1.2.840.113549.1.1.11" { $HashFunction = [System.Security.Cryptography.SHA256]::Create() }
        "1.2.840.113549.1.1.12" { $HashFunction = [System.Security.Cryptography.SHA384]::Create() }    
        "1.2.840.113549.1.1.13" { $HashFunction = [System.Security.Cryptography.SHA512]::Create() }
        default { throw "No handler for algorithm $AlgorithmOid" }
    }
    
    # Compute the hash of the TBS value using the hash function
    $Hash = $HashFunction.ComputeHash($TbsCertificate.ToArray())    
    
    # Convert the hash to a hex string and return it
    return [System.BitConverter]::ToString($hash) -replace "-", ""
}


# Helps get the 2nd aka nested signer/signature of the dual signed files
function Get-AuthenticodeSignatureEx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]$FilePath
    )
    begin {
        $signature = @"
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptQueryObject(
        int dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)]
        string pvObject,
        int dwExpectedContentTypeFlags,
        int dwExpectedFormatTypeFlags,
        int dwFlags,
        ref int pdwMsgAndCertEncodingType,
        ref int pdwContentType,
        ref int pdwFormatType,
        ref IntPtr phCertStore,
        ref IntPtr phMsg,
        ref IntPtr ppvContext
    );
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptMsgGetParam(
        IntPtr hCryptMsg,
        int dwParamType,
        int dwIndex,
        byte[] pvData,
        ref int pcbData
    );
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptMsgClose(
        IntPtr hCryptMsg
    );
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CertCloseStore(
        IntPtr hCertStore,
        int dwFlags
    );
"@
        Add-Type -AssemblyName System.Security
        Add-Type -MemberDefinition $signature -Namespace PKI -Name Crypt32
        $CERT_QUERY_OBJECT_FILE = 0x1
        $CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
        $CERT_QUERY_FORMAT_FLAG_BINARY = 0x2
            
        function getTimeStamps($SignerInfo) {
            $retValue = @()
            foreach ($CounterSignerInfos in $Infos.CounterSignerInfos) {                    
                $sTime = ($CounterSignerInfos.SignedAttributes | Where-Object { $_.Oid.Value -eq "1.2.840.113549.1.9.5" }).Values | `
                    Where-Object { $null -ne $_.SigningTime }
                $tsObject = New-Object psobject -Property @{
                    Certificate = $CounterSignerInfos.Certificate
                    SigningTime = $sTime.SigningTime.ToLocalTime()
                }
                $retValue += $tsObject
            }
            $retValue
        }
    }
    process {
        Get-AuthenticodeSignature $FilePath | ForEach-Object {
            $Output = $_
            if ($null -ne $Output.SignerCertificate) {              
                $pdwMsgAndCertEncodingType = 0
                $pdwContentType = 0
                $pdwFormatType = 0
                [IntPtr]$phCertStore = [IntPtr]::Zero
                [IntPtr]$phMsg = [IntPtr]::Zero
                [IntPtr]$ppvContext = [IntPtr]::Zero
                $return = [PKI.Crypt32]::CryptQueryObject(
                    $CERT_QUERY_OBJECT_FILE,
                    $Output.Path,
                    $CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    $CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    [ref]$pdwMsgAndCertEncodingType,
                    [ref]$pdwContentType,
                    [ref]$pdwFormatType,
                    [ref]$phCertStore,
                    [ref]$phMsg,
                    [ref]$ppvContext
                )
                if (!$return) { return }
                $pcbData = 0
                $return = [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $null, [ref]$pcbData)
                if (!$return) { return }
                $pvData = New-Object byte[] -ArgumentList $pcbData
                $return = [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $pvData, [ref]$pcbData)
                $SignedCms = New-Object Security.Cryptography.Pkcs.SignedCms
                $SignedCms.Decode($pvData)
                $Infos = $SignedCms.SignerInfos[0]
                $Output | Add-Member -MemberType NoteProperty -Name TimeStamps -Value $null
                $Output | Add-Member -MemberType NoteProperty -Name DigestAlgorithm -Value $Infos.DigestAlgorithm.FriendlyName
                $Output.TimeStamps = getTimeStamps $Infos
                $second = $Infos.UnsignedAttributes | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.2.4.1" }
                if ($second) {
                    $value = $second.Values | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.2.4.1" }
                    $SignedCms2 = New-Object Security.Cryptography.Pkcs.SignedCms
                    $SignedCms2.Decode($value.RawData)
                    $Output | Add-Member -MemberType NoteProperty -Name NestedSignature -Value $null
                    $Infos = $SignedCms2.SignerInfos[0]
                    $nested = New-Object psobject -Property @{
                        SignerCertificate = $Infos.Certificate
                        DigestAlgorithm   = $Infos.DigestAlgorithm.FriendlyName
                        TimeStamps        = getTimeStamps $Infos
                    }
                    $Output.NestedSignature = $nested
                }
                $Output
                [void][PKI.Crypt32]::CryptMsgClose($phMsg)
                [void][PKI.Crypt32]::CertCloseStore($phCertStore, 0)
            }
            else {
                $Output
            }
        }
    }
    end {}
}



# Function that shows the details of certificates. E.g, All intermediate cers, Leaf cert or the entire chain, depending on optional switch parameters
function Get-CertificateDetails {
    # Use the param keyword to define the parameters
    param (
        # Make the FilePath parameter mandatory and validate that it is a valid file path
        [Parameter()]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$FilePath,
        $X509Certificate2,  
        [switch]$IntermediateOnly,
        [switch]$AllCertificates,
        [switch]$LeafCertificate
    )

    if ($FilePath) {
        # Get the certificate from the file path
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $FilePath
    }
    # if file path isn't used and instead a X509Certificate2 is provided then assign it directly to the $Cert variable
    elseif ($X509Certificate2) {
        $Cert = $X509Certificate2
    }
  
    # Build the certificate chain
    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    [void]$Chain.Build($Cert)
  
    # Check the value of the switch parameters
    if ($IntermediateOnly) {
        # If IntermediateOnly is present, loop through the chain elements and display only the intermediate certificates
        for ($i = 1; $i -lt $Chain.ChainElements.Count - 1; $i++) {
            # Create a custom object with the certificate properties
            $Element = $Chain.ChainElements[$i]
            # Extract the data after CN= in the subject and issuer properties
            $SubjectCN = ($Element.Certificate.Subject -split '(?:^|,)CN=|,')[1]
            $IssuerCN = ($Element.Certificate.Issuer -split '(?:^|,)CN=|,')[1]
            # Get the TBS value of the certificate using the Get-TBSCertificate function
            $TbsValue = Get-TBSCertificate -cert $Element.Certificate
            # Create a custom object with the extracted properties and the TBS value
            $Obj = [pscustomobject]@{
                SubjectCN = $SubjectCN
                IssuerCN  = $issuerCN
                NotAfter  = $Element.Certificate.NotAfter
                TBSValue  = $TbsValue
            }
            # Display the object
            Write-Output $Obj
        }
    }
    elseif ($AllCertificates) {
        # If AllCertificates is present, loop through all chain elements and display all certificates
        foreach ($Element in $Chain.ChainElements) {
            # Create a custom object with the certificate properties
            # Extract the data after CN= in the subject and issuer properties
            $SubjectCN = ($Element.Certificate.Subject -split '(?:^|,)CN=|,')[1]
            $IssuerCN = ($Element.Certificate.Issuer -split '(?:^|,)CN=|,')[1]
            # Get the TBS value of the certificate using the Get-TBSCertificate function
            $TbsValue = Get-TBSCertificate -cert $Element.Certificate
            # Create a custom object with the extracted properties and the TBS value
            $Obj = [pscustomobject]@{
                SubjectCN = $SubjectCN
                IssuerCN  = $IssuerCN
                NotAfter  = $element.Certificate.NotAfter
                TBSValue  = $TbsValue
            }
            # Display the object
            Write-Output $obj
        }
    }
    elseif ($LeafCertificate) {
        # If LeafCertificate is present, create a custom object with the leaf certificate properties
        # Extract the data after CN= in the subject and issuer properties
        $SubjectCN = ($Chain.ChainElements[0].Certificate.Subject -split '(?:^|,)CN=|,')[1]
        $IssuerCN = ($Chain.ChainElements[0].Certificate.Issuer -split '(?:^|,)CN=|,')[1]
        # Get the TBS value of the certificate using the Get-TBSCertificate function
        $TbsValue = Get-TBSCertificate -cert $Chain.ChainElements[0].Certificate
        # Create a custom object with the extracted properties and the TBS value
        $Obj = [pscustomobject]@{
            SubjectCN = $SubjectCN
            IssuerCN  = $IssuerCN
            NotAfter  = $Chain.ChainElements[0].Certificate.NotAfter
            TBSValue  = $TbsValue
        }
        # Display the object
        Write-Output "Leaf Certificate:"
        Write-Output $obj    
    }
    else {
        # If none of the switch parameters are present, display a message to inform the user of their options
        Write-Output "Please specify one of the following switch parameters to get certificate details: -IntermediateOnly, -AllCertificates, or -LeafCertificate."
    }
}
  




# Define a function that takes two file paths as input and compares the output of the Get-SignerInfo and Get-CertificateDetails functions
function Compare-SignerAndCertificate {
    param(
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [Parameter(Mandatory = $true)][string]$XmlFilePath,

        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [Parameter(Mandatory = $true)] [string]$SignedFilePath
    )
  
    # Get the signer information from the XML file path using the Get-SignerInfo function
    $SignerInfo = Get-SignerInfo -XmlFilePath $XmlFilePath
  
    
    # Declare $CertificateDetails as an array
    $CertificateDetails = @()

    # Get the certificate details from the signed file path using the Get-CertificateDetails function with the IntermediateOnly switch parameter
    $CertificateDetails += Get-CertificateDetails -IntermediateOnly -FilePath $SignedFilePath

    if ($null -ne (Get-AuthenticodeSignatureEx -FilePath $SignedFilePath).NestedSignature.SignerCertificate) {
        # append an X509Certificate2 object to the array
        $CertificateDetails += Get-CertificateDetails -IntermediateOnly -X509Certificate2 $((Get-AuthenticodeSignatureEx -FilePath $SignedFilePath).NestedSignature.SignerCertificate)
    }


  
    # Create an empty array to store the comparison results
    $ComparisonResults = @()
  
    # Loop through each signer in the signer information array
    foreach ($Signer in $SignerInfo) {
        # Create a custom object to store the comparison result for this signer
        $ComparisonResult = [pscustomobject]@{
            SignerID            = $Signer.ID
            SignerName          = $Signer.Name
            SignerCertRoot      = $Signer.CertRoot
            SignerCertPublisher = $Signer.CertPublisher
            CertSubjectCN       = $null
            CertIssuerCN        = $null
            CertNotAfter        = $null
            CertTBSValue        = $null
            CertRootMatch       = $false
            CertNameMatch       = $false
            CertPublisherMatch  = $false
            FilePath            = $SignedFilePath # Add the file path to the object
        }
  
        # Loop through each certificate in the certificate details array
        foreach ($Certificate in $CertificateDetails) {
            # Check if the signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)...
            # ...matches the TBSValue of the file's certificate (TBS values of one of the intermediate certificates of the file since -IntermediateOnly parameter is used earlier and that's what FilePublisher level uses)
            # So this checks to see if the Signer's TBS value in xml matches any of the TBS value(s) of the file's intermediate certificate(s), if yes, that means that file is allowed to run by WDAC engine
            if ($Signer.CertRoot -eq $Certificate.TBSValue) {
                # If yes, assign the certificate properties to the comparison result object and set the CertRootMatch to true
                $ComparisonResult.CertSubjectCN = $Certificate.SubjectCN
                $ComparisonResult.CertIssuerCN = $Certificate.IssuerCN
                $ComparisonResult.CertNotAfter = $Certificate.NotAfter
                $ComparisonResult.CertTBSValue = $Certificate.TBSValue
                $ComparisonResult.CertRootMatch = $true # meaning one of the TBS values of the file's intermediate certs is in the xml file signers's TBS values
  
                # Check if the signer's Name matches the certificate's SubjectCN
                if ($Signer.Name -eq $Certificate.SubjectCN) {
                    # If yes, set the CertNameMatch to true
                    $ComparisonResult.CertNameMatch = $true # this should naturally be always true like the CertRootMatch because this is the CN of the same cert that has its TBS value in the xml file in signers
                }
  
                # Break out of the inner loop since we found a match for this signer
                break
            }
        }
  
        # Add the comparison result object to the comparison results array
        $ComparisonResults += $ComparisonResult
  
    }

    # Declare $LeafCertificateDetails as an array
    $LeafCertificateDetails = @()
  
    # Get the leaf certificate details from the signed file path
    $LeafCertificateDetails += Get-CertificateDetails -LeafCertificate -FilePath $SignedFilePath


    if ($null -ne (Get-AuthenticodeSignatureEx -FilePath $SignedFilePath).NestedSignature.SignerCertificate) {
        # Use += to append an X509Certificate2 object to the array
        $CertificateDetails += Get-CertificateDetails -LeafCertificate -X509Certificate2 $((Get-AuthenticodeSignatureEx -FilePath $SignedFilePath).NestedSignature.SignerCertificate)
    }

  
    # Loop through each signer in the signer information array again
    foreach ($Signer in $SignerInfo) {
        # Find the corresponding comparison result object for this signer in the comparison results array
        $ComparisonResult = $ComparisonResults | Where-Object { $_.SignerID -eq $Signer.ID }
 
        # Loop through each item in the leaf certificate details array
        foreach ($LeafCertificate in $LeafCertificateDetails) {
            # Check if the signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the leaf certificate's SubjectCN (of the file)
            if ($Signer.CertPublisher -eq $LeafCertificate.SubjectCN) {
                # If yes, set the CertPublisherMatch to true for this comparison result object 
                $ComparisonResult.CertPublisherMatch = $true      
            }
        }
    }

    # Return the comparison results array
    return $ComparisonResults
  
}  
  
