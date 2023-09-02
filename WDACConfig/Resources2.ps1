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
    [System.Object[]]$output = @()
  
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
        '1.2.840.113549.1.1.4' { $HashFunction = [System.Security.Cryptography.MD5]::Create() }
        '1.2.840.10040.4.3' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() }
        '2.16.840.1.101.3.4.3.2' { $HashFunction = [System.Security.Cryptography.SHA256]::Create() }
        '2.16.840.1.101.3.4.3.3' { $HashFunction = [System.Security.Cryptography.SHA384]::Create() }
        '2.16.840.1.101.3.4.3.4' { $HashFunction = [System.Security.Cryptography.SHA512]::Create() }
        '1.2.840.10045.4.1' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() }
        '1.2.840.10045.4.3.2' { $HashFunction = [System.Security.Cryptography.SHA256]::Create() }
        '1.2.840.10045.4.3.3' { $HashFunction = [System.Security.Cryptography.SHA384]::Create() }
        '1.2.840.10045.4.3.4' { $HashFunction = [System.Security.Cryptography.SHA512]::Create() }
        '1.2.840.113549.1.1.5' { $HashFunction = [System.Security.Cryptography.SHA1]::Create() }
        '1.2.840.113549.1.1.11' { $HashFunction = [System.Security.Cryptography.SHA256]::Create() }
        '1.2.840.113549.1.1.12' { $HashFunction = [System.Security.Cryptography.SHA384]::Create() }    
        '1.2.840.113549.1.1.13' { $HashFunction = [System.Security.Cryptography.SHA512]::Create() }
        default { throw "No handler for algorithm $AlgorithmOid" }
    }
    
    # Compute the hash of the TBS value using the hash function
    $Hash = $HashFunction.ComputeHash($TbsCertificate.ToArray())    
    
    # Convert the hash to a hex string and return it
    return [System.BitConverter]::ToString($hash) -replace '-', ''
}


# Helps get the 2nd aka nested signer/signature of the dual signed files
# https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx
# https://www.sysadmins.lv/disclaimer.aspx
function Get-AuthenticodeSignatureEx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]$FilePath # The path of the file(s) to get the signature of
    )
    begin {
        # Define the signature of the Crypt32.dll library functions to use
        $signature = @'
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
'@
        # Load the System.Security assembly to use the SignedCms class
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        # Add the Crypt32.dll library functions as a type
        Add-Type -MemberDefinition $signature -Namespace PKI -Name Crypt32 -ErrorAction SilentlyContinue
        # Define some constants for the CryptQueryObject function parameters
        $CERT_QUERY_OBJECT_FILE = 0x1
        $CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400
        $CERT_QUERY_FORMAT_FLAG_BINARY = 0x2
            
        # Define a helper function to get the timestamps of the countersigners
        function getTimeStamps($SignerInfo) {
            [System.Object[]]$retValue = @()
            foreach ($CounterSignerInfos in $Infos.CounterSignerInfos) {                    
                # Get the signing time attribute from the countersigner info object
                $sTime = ($CounterSignerInfos.SignedAttributes | Where-Object { $_.Oid.Value -eq '1.2.840.113549.1.9.5' }).Values | `
                    Where-Object { $null -ne $_.SigningTime }
                # Create a custom object with the countersigner certificate and signing time properties
                $tsObject = New-Object psobject -Property @{
                    Certificate = $CounterSignerInfos.Certificate
                    SigningTime = $sTime.SigningTime.ToLocalTime()
                }
                # Add the custom object to the return value array
                $retValue += $tsObject
            }
            # Return the array of custom objects with countersigner info
            $retValue

        }
    }
    process {
        # For each file path, get the authenticode signature using the built-in cmdlet
        Get-AuthenticodeSignature $FilePath | ForEach-Object {
            $Output = $_ # Store the output object in a variable
            if ($null -ne $Output.SignerCertificate) {
                # If the output object has a signer certificate property
                # Initialize some variables to store the output parameters of the CryptQueryObject function
                $pdwMsgAndCertEncodingType = 0
                $pdwContentType = 0
                $pdwFormatType = 0
                [IntPtr]$phCertStore = [IntPtr]::Zero
                [IntPtr]$phMsg = [IntPtr]::Zero
                [IntPtr]$ppvContext = [IntPtr]::Zero
                # Call the CryptQueryObject function to get the handle of the PKCS #7 message from the file path
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
                if (!$return) { return } # If the function fails, return nothing
                $pcbData = 0 # Initialize a variable to store the size of the PKCS #7 message data
                # Call the CryptMsgGetParam function to get the size of the PKCS #7 message data
                $return = [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $null, [ref]$pcbData)
                if (!$return) { return } # If the function fails, return nothing
                $pvData = New-Object byte[] -ArgumentList $pcbData # Create a byte array to store the PKCS #7 message data
                # Call the CryptMsgGetParam function again to get the PKCS #7 message data
                $return = [PKI.Crypt32]::CryptMsgGetParam($phMsg, 29, 0, $pvData, [ref]$pcbData)
                $SignedCms = New-Object Security.Cryptography.Pkcs.SignedCms # Create a SignedCms object to decode the PKCS #7 message data
                $SignedCms.Decode($pvData) # Decode the PKCS #7 message data and populate the SignedCms object properties
                $Infos = $SignedCms.SignerInfos[0] # Get the first signer info object from the SignedCms object
                # Add some properties to the output object, such as TimeStamps, DigestAlgorithm and NestedSignature
                $Output | Add-Member -MemberType NoteProperty -Name TimeStamps -Value $null
                $Output | Add-Member -MemberType NoteProperty -Name DigestAlgorithm -Value $Infos.DigestAlgorithm.FriendlyName
                # Call the helper function to get the timestamps of the countersigners and assign it to the TimeStamps property
                $Output.TimeStamps = getTimeStamps $Infos 
                # Check if there is a nested signature attribute in the signer info object by looking for the OID 1.3.6.1.4.1.311.2.4.1
                $second = $Infos.UnsignedAttributes | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1' }
                if ($second) {
                    # If there is a nested signature attribute
                    # Get the value of the nested signature attribute as a raw data byte array
                    $value = $second.Values | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1' }
                    $SignedCms2 = New-Object Security.Cryptography.Pkcs.SignedCms # Create another SignedCms object to decode the nested signature data
                    $SignedCms2.Decode($value.RawData) # Decode the nested signature data and populate the SignedCms object properties
                    $Output | Add-Member -MemberType NoteProperty -Name NestedSignature -Value $null 
                    $Infos = $SignedCms2.SignerInfos[0] # Get the first signer info object from the nested signature SignedCms object
                    # Create a custom object with some properties of the nested signature, such as signer certificate, digest algorithm and timestamps
                    $nested = New-Object psobject -Property @{
                        SignerCertificate = $Infos.Certificate
                        DigestAlgorithm   = $Infos.DigestAlgorithm.FriendlyName
                        TimeStamps        = getTimeStamps $Infos
                    }
                    # Assign the custom object to the NestedSignature property of the output object
                    $Output.NestedSignature = $nested
                }
                # Return the output object with the added properties
                $Output
                # Close the handles of the PKCS #7 message and the certificate store
                [void][PKI.Crypt32]::CryptMsgClose($phMsg)
                [void][PKI.Crypt32]::CertCloseStore($phCertStore, 0)
            }
            else {
                # If the output object does not have a signer certificate property
                # Return the output object as it is
                $Output
            }
        }
    }
    end {}
}



# Function that shows the details of certificates. E.g, All intermediate certs, Leaf cert or the entire chain, depending on optional switch parameters
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
        Write-Output 'Leaf Certificate:'
        Write-Output $obj    
    }
    else {
        # If none of the switch parameters are present, display a message to inform the user of their options
        Write-Output 'Please specify one of the following switch parameters to get certificate details: -IntermediateOnly, -AllCertificates, or -LeafCertificate.'
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
    [System.Object[]]$CertificateDetails = @()

    # Declare $NestedCertificateDetails as an array 
    [System.Object[]]$NestedCertificateDetails = @()

    # Get the certificate details from the signed file path using the Get-CertificateDetails function with the IntermediateOnly switch parameter
    $CertificateDetails += Get-CertificateDetails -IntermediateOnly -FilePath $SignedFilePath

    $ExtraCertificateDetails = Get-AuthenticodeSignatureEx -FilePath $SignedFilePath

    $NestedCertificate = ($ExtraCertificateDetails).NestedSignature.SignerCertificate

    # Store Intermediate Certificate details of the 2nd certificate into another array variable if it exists
    if ($null -ne $NestedCertificate) {
        # append an X509Certificate2 object to the array
        $NestedCertificateDetails += Get-CertificateDetails -IntermediateOnly -X509Certificate2 $NestedCertificate
    }


  
    # Create an empty array to store the comparison results
    [System.Object[]]$ComparisonResults = @()
  
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
  
        # Loop through each certificate in the certificate details array of the Main Cert
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
                # if file has nested signature, only set a flag instead of setting the entire property to true
                if ($null -ne $NestedCertificate) {
                    $CertRootMatchPart1 = $true
                }
                else {
                    $ComparisonResult.CertRootMatch = $true # meaning one of the TBS values of the file's intermediate certs is in the xml file signers's TBS values
                }

                # Check if the signer's Name matches the Intermediate certificate's SubjectCN
                if ($Signer.Name -eq $Certificate.SubjectCN) {
                    # If yes, set the CertNameMatch to true
                    $ComparisonResult.CertNameMatch = $true # this should naturally be always true like the CertRootMatch because this is the CN of the same cert that has its TBS value in the xml file in signers
                }
  
                # Break out of the inner loop since we found a match for this signer
                break
            }
        }






        # Nested Certificate TBS processing
        if ($null -ne $NestedCertificate) {

            # Loop through each certificate in the NESTED certificate details array
            foreach ($Certificate in $NestedCertificateDetails) {
                # Check if the signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file)...
                # ...matches the TBSValue of the file's certificate (TBS values of one of the intermediate certificates of the file since -IntermediateOnly parameter is used earlier and that's what FilePublisher level uses)
                # So this checks to see if the Signer's TBS value in xml matches any of the TBS value(s) of the file's intermediate certificate(s), if yes, that means that file is allowed to run by WDAC engine
                if ($Signer.CertRoot -eq $Certificate.TBSValue) {
                    # If yes, assign the certificate properties to the comparison result object and set the CertRootMatch to true
                    $ComparisonResult.CertSubjectCN = $Certificate.SubjectCN
                    $ComparisonResult.CertIssuerCN = $Certificate.IssuerCN
                    $ComparisonResult.CertNotAfter = $Certificate.NotAfter
                    $ComparisonResult.CertTBSValue = $Certificate.TBSValue       
                    # When file has nested signature, only set a flag instead of setting the entire property to true             
                    $CertRootMatchPart2 = $true

                    # Check if the signer's Name matches the Intermediate certificate's SubjectCN
                    if ($Signer.Name -eq $Certificate.SubjectCN) {
                        # If yes, set the CertNameMatch to true
                        $ComparisonResult.CertNameMatch = $true # this should naturally be always true like the CertRootMatch because this is the CN of the same cert that has its TBS value in the xml file in signers
                    }
  
                    # Break out of the inner loop since we found a match for this signer
                    break
                }
            }
        }



        # if file has nested certificates
        if ($null -ne $NestedCertificate) {
            # check if both of the file's nested certificates are available in the Signers in xml policy
            if ( $CertRootMatchPart1 -eq $true -and $CertRootMatchPart2 -eq $true) {
                $ComparisonResult.CertRootMatch = $true # meaning all of the TBS values of the double signed file's intermediate certificates exists in the xml file's signers' TBS values
                                                        
            }
            else {
                $ComparisonResult.CertRootMatch = $false 
            }
        }
        






        # Add the comparison result object to the comparison results array
        $ComparisonResults += $ComparisonResult
  
    }

    # Declare $LeafCertificateDetails as an array
    [System.Object[]]$LeafCertificateDetails = @()

    # Declare $NestedLeafCertificateDetails as an array
    [System.Object[]]$NestedLeafCertificateDetails = @()
  
    # Get the leaf certificate details from the signed file path
    $LeafCertificateDetails += Get-CertificateDetails -LeafCertificate -FilePath $SignedFilePath


    # Store Leaf Certificate details of the 2nd certificate into another array variable if it exists
    if ($null -ne $NestedCertificate) {
        # append an X509Certificate2 object to the array
        $NestedLeafCertificateDetails += Get-CertificateDetails -LeafCertificate -X509Certificate2 $NestedCertificate
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
  


# HASH COMPARISON FUNCTIONS

# Define a function to load an xml file and create an output array of custom objects
function Get-FileRuleOutput ($xmlPath) {

    # Load the xml file into a variable
    $xml = [xml](Get-Content -Path $xmlPath)

    # Create an empty array to store the output
    [System.Object[]]$OutPutHashInfoProcessing = @()

    # Loop through each file rule in the xml file
    foreach ($filerule in $xml.SiPolicy.FileRules.Allow) {

        # Extract the hash value from the Hash attribute
        $hashvalue = $filerule.Hash

        # Extract the hash type from the FriendlyName attribute using regex
        $hashtype = $filerule.FriendlyName -replace '.* (Hash (Sha1|Sha256|Page Sha1|Page Sha256))$', '$1'

        # Extract the file path from the FriendlyName attribute using regex
        # $FilePathForHash = $filerule.FriendlyName -replace " (.*) (Hash (Sha1|Sha256|Page Sha1|Page Sha256))$", '$1'

        $FilePathForHash = $filerule.FriendlyName -replace ' (Hash (Sha1|Sha256|Page Sha1|Page Sha256))$', ''
       
        # Create a custom object with the three properties
        $object = [PSCustomObject]@{
            HashValue       = $hashvalue
            HashType        = $hashtype
            FilePathForHash = $FilePathForHash
        }

        # Add the object to the output array if it is not a duplicate hash value
        if ($OutPutHashInfoProcessing.HashValue -notcontains $hashvalue) {
            $OutPutHashInfoProcessing += $object
        }
    }

    # Return the output array
    return $OutPutHashInfoProcessing
}


# Define a function to compare two xml files and return an array of objects with a custom property for the comparison result
function Compare-XmlFiles ($refXmlPath, $tarXmlPath) {

    # Load the reference xml file and create an output array using the Get-FileRuleOutput function
    $refoutput = Get-FileRuleOutput -xmlPath $refXmlPath

    # Load the target xml file and create an output array using the Get-FileRuleOutput function
    $taroutput = Get-FileRuleOutput -xmlPath $tarXmlPath

    # make sure they are not empty
    if ($refoutput -and $taroutput) {

        # Compare the output arrays using the Compare-Object cmdlet with the -Property parameter
        # Specify the HashValue property as the property to compare
        # Use the -PassThru parameter to return the original input objects
        # Use the -IncludeEqual parameter to include the objects that are equal in both arrays
        $comparison = Compare-Object -ReferenceObject $refoutput -DifferenceObject $taroutput -Property HashValue -PassThru -IncludeEqual

        # Create an empty array to store the output objects
        [System.Object[]]$OutPutHashComparison = @()

        # Loop through each object in the comparison array
        foreach ($object in $comparison) {

            # Create a custom property called Comparison and assign it a value based on the SideIndicator property
            switch ($object.SideIndicator) {
                '<=' { $comparison = 'Only in reference' }
                '=>' { $comparison = 'Only in target' }
                '==' { $comparison = 'Both' }
            }

            # Add the Comparison property to the object using the Add-Member cmdlet
            $object | Add-Member -MemberType NoteProperty -Name Comparison -Value $comparison

            # Add the object to the output array
            $OutPutHashComparison += $object
        }

        # Return the output array
        return $OutPutHashComparison

    }
}



