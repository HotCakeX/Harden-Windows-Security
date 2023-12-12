<#

The following file contains functions related to Resources2.ps1 file in the WDACConfig module
that were used mainly by the Invoke-WDACSimulation cmdlet

#>


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
        [System.Object[]]$OutputHashComparison = @()

        # Loop through each object in the comparison array
        foreach ($Object in $comparison) {

            # Create a custom property called Comparison and assign it a value based on the SideIndicator property
            switch ($Object.SideIndicator) {
                '<=' { $comparison = 'Only in reference' }
                '=>' { $comparison = 'Only in target' }
                '==' { $comparison = 'Both' }
            }

            # Add the Comparison property to the object using the Add-Member cmdlet
            $Object | Add-Member -MemberType NoteProperty -Name Comparison -Value $comparison

            # Add the object to the output array
            $OutputHashComparison += $Object
        }

        # Return the output array
        return $OutputHashComparison

    }
}

# Function that shows the details of certificates. E.g, All intermediate certs, Leaf cert or the entire chain, depending on optional switch parameters
function Get-CertificateDetails {
    # Use the param keyword to define the parameters
    param (
        # Make the FilePath parameter mandatory and validate that it is a valid file path
        [Parameter()]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.String]$FilePath,
        $X509Certificate2,
        [System.Management.Automation.SwitchParameter]$IntermediateOnly,
        [System.Management.Automation.SwitchParameter]$AllCertificates,
        [System.Management.Automation.SwitchParameter]$LeafCertificate
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
    $Chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

    # Set the chain policy properties
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $chain.ChainPolicy.RevocationFlag = 'EndCertificateOnly'
    $chain.ChainPolicy.VerificationFlags = 'NoFlag'

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
            Write-Output -InputObject $Obj
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
            Write-Output -InputObject $obj
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
        Write-Output -InputObject 'Leaf Certificate:'
        Write-Output -InputObject $obj
    }
    else {
        # If none of the switch parameters are present, display a message to inform the user of their options
        Write-Output -InputObject 'Please specify one of the following switch parameters to get certificate details: -IntermediateOnly, -AllCertificates, or -LeafCertificate.'
    }
}

